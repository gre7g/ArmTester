import logging
import re
import unicorn
import unicorn.arm_const as arm

FUNCTION_BEGIN = re.compile(r"^([0-9a-f]{8}) <(\w+)>:")
LINE = re.compile(r"^\s+([0-9a-f]+):\s+([0-9a-f]+) ([0-9a-f]{4})?\s+\S+(.*)")
REGISTER_PORTION = re.compile(r"^\s+r(\d+),")

FLASH_START = 0x00000000
FLASH_SIZE = 1024 * 1024
RAM_START = 0x20000000
RAM_SIZE = 128 * 1024
REGISTER_START = 0x40000000
REGISTER_SIZE = 0xe6400
END_OF_EXECUTION = 0x30000000  # special token

LOG = logging.getLogger(__name__)


class Unsigned16(object):
    def __init__(self, name=None):
        self.name = name

    def decode(self, value):
        return str(value)

    def return_value(self, value, program):
        program.uc.reg_write(arm.UC_ARM_REG_R0, value)


class Instruction(object):
    def __init__(self, match, lines_before=""):
        self.text = match.string.rstrip()
        self.addr = int(match.group(1), 16)
        self.register = None
        self.lines_before = lines_before
        if match.group(4):
            match = REGISTER_PORTION.search(match.group(4))
            if match:
                self.register = int(match.group(1))


class Function(object):
    def __init__(self, match):
        addr, self.name = match.groups()
        self.addr = int(addr, 16)


class Parameter(object):
    def __init__(self, index, type_obj):
        self.index, self.type_obj = index, type_obj

    def decode(self, program):
        value = program.uc.reg_read(arm.UC_ARM_REG_R0 + self.index)  # TODO: maximum?
        return self.type_obj.decode(value)


class Prototype(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.params = tuple(Parameter(index, arg) for index, arg in enumerate(args))
        self.returns = kwargs.get("returns")

    def log_entry(self, program):
        params = ", ".join(param.decode(program) for param in self.params)
        LOG.info("entered %s(%s)", self.func, params)

    def return_value(self, value, program):
        self.returns.return_value(value, program)


class Patch(object):
    def __init__(self, prototype, mock):
        self.prototype, self.mock = prototype, mock

    def execute(self, program):
        self.prototype.return_value(self.mock(), program)


class Program(object):
    def __init__(self, disassembly, binary):
        self.funcs_by_name = {}
        self.funcs_by_addr = {}
        self.inst_by_addr = {}
        self.protos_by_name = {}
        self.register_to_log = None
        self.first_instruction = True
        self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
        self.break_points = []
        self.patches_by_addr = {}

        # Allocate memory
        self.uc.mem_map(FLASH_START, FLASH_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.uc.mem_map(RAM_START, RAM_SIZE, unicorn.UC_PROT_ALL)
        self.uc.mem_map(REGISTER_START, REGISTER_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.uc.mem_map(END_OF_EXECUTION, 1024, unicorn.UC_PROT_EXEC)

        # Load code
        with open(binary, "rb") as file_obj:
            self.uc.mem_write(FLASH_START, file_obj.read())

        # Hook handler
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)

        self.parse_disassembly(disassembly)

    def parse_disassembly(self, disassembly):
        lines_before = ""
        with open(disassembly, "rt") as file_obj:
            while True:
                line = file_obj.readline()
                if not line:
                    break

                match = FUNCTION_BEGIN.search(line)
                if match:
                    function = Function(match)
                    if function.name not in self.funcs_by_name:
                        self.funcs_by_name[function.name] = function
                        self.funcs_by_addr[function.addr] = function
                else:
                    match = LINE.search(line)
                    if match:
                        instruction = Instruction(match, lines_before)
                        if instruction.addr not in self.inst_by_addr:
                            self.inst_by_addr[instruction.addr] = instruction
                        lines_before = ""
                    else:
                        if lines_before or (line != "\n"):
                            lines_before += line

    def hook_code(self, uc, address, size, user_data):
        if self.first_instruction:
            self.first_instruction = False

            if self.register_to_log is not None:
                LOG.debug("r%d = %08x", self.register_to_log, uc.reg_read(arm.UC_ARM_REG_R0 + self.register_to_log))
                self.register_to_log = None
            if address in self.inst_by_addr:
                instruction = self.inst_by_addr[address]
                if instruction.lines_before:
                    for line in instruction.lines_before[:-1].split("\n"):
                        LOG.info("%s", line)
                LOG.info("%s", instruction.text)
                self.register_to_log = instruction.register
            else:
                LOG.warning("Fetched unknown instruction at %x", address)

    def set_sp(self, addr):
        self.uc.reg_write(arm.UC_ARM_REG_SP, addr)

    def start(self, func):
        # Note we start at ADDRESS | 1 to indicate THUMB mode
        self.uc.reg_write(arm.UC_ARM_REG_LR, END_OF_EXECUTION | 1)
        self.first_instruction = True
        self.uc.emu_start(self.funcs_by_name[func].addr | 1, 4, count=1)

    def step(self):
        self.first_instruction = True
        pc = self.uc.reg_read(arm.UC_ARM_REG_PC)
        # Note we start at ADDRESS | 1 to indicate THUMB mode.
        self.uc.emu_start(pc | 1, 4, count=1)

    def run(self, func):
        self.start(func)
        while True:
            pc = self.uc.reg_read(arm.UC_ARM_REG_PC)
            if pc == END_OF_EXECUTION:
                LOG.debug("execution complete")
                break
            elif pc in self.break_points:
                func = self.funcs_by_addr[pc]
                self.protos_by_name[func.name].log_entry(self)
                LOG.info("breakpoint hit: 0x%x", pc)
                break
            elif pc in self.patches_by_addr:
                patch = self.patches_by_addr[pc]
                patch.execute(self)
                lr = self.uc.reg_read(arm.UC_ARM_REG_LR)
                self.first_instruction = True
                self.uc.emu_start(lr, 4, count=1)
            else:
                self.first_instruction = True
                self.uc.emu_start(pc | 1, 4, count=1)

    def set_breakpoints(self, break_points):
        self.break_points = []
        for func in break_points:
            assert func in self.protos_by_name, ('No prototype known for function "%s"' % func)
            self.break_points.append(self.funcs_by_name[func].addr)

    def set_func_proto(self, func, *args, **kwargs):
        prototype = Prototype(func, *args, **kwargs)
        self.protos_by_name[func] = prototype

    def patch(self, func, mock):
        assert func in self.protos_by_name, ('No prototype known for function "%s"' % func)
        self.patches_by_addr[self.funcs_by_name[func].addr] = Patch(self.protos_by_name[func], mock)
