import logging
from mock import Mock
import re
import unicorn
import unicorn.arm_const as arm

from arm_tester.types import Prototype

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
MAX_INSTRUCTIONS = 1000000

LOG = logging.getLogger(__name__)


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


class Patch(object):
    def __init__(self, prototype, mock):
        self.prototype, self.mock = prototype, mock
        self.restore_instr = None

    def execute(self, program, *args):
        return_value = self.mock(*args)
        self.prototype.log_entry(program, return_value=return_value)
        self.prototype.return_value(return_value, program)


class Program(object):
    def __init__(self, disassembly, binary):
        self.funcs_by_name = {}
        self.funcs_by_addr = {}
        self.inst_by_addr = {}
        self.protos_by_name = {}
        self.register_to_log = None
        self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
        self.patches_by_addr = {}
        self.mocks = Mock()
        self.heap = None

        # Allocate memory
        self.uc.mem_map(FLASH_START, FLASH_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.uc.mem_map(RAM_START, RAM_SIZE, unicorn.UC_PROT_ALL)
        self.uc.mem_map(REGISTER_START, REGISTER_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

        # Load code
        with open(binary, "rb") as file_obj:
            self.uc.mem_write(FLASH_START, file_obj.read())

        # Hook handler
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)

        self.parse_disassembly(disassembly)

    def set_heap(self, addr):
        self.heap = addr

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

    def run(self, prototype, *args, **kwargs):
        max_instructions = kwargs.get("max_instructions", MAX_INSTRUCTIONS)
        prototype.set_args(*args)

        # Set the link location to a specific, bad address. We'll look for a bad fetch from here to know that the
        # function has completed and tried to return. Note we start at ADDRESS | 1 to indicate THUMB mode.
        self.uc.reg_write(arm.UC_ARM_REG_LR, END_OF_EXECUTION | 1)
        self.uc.reg_write(arm.UC_ARM_REG_PC, self.funcs_by_name[prototype.func].addr)

        while True:
            try:
                self.uc.emu_start(self.uc.reg_read(arm.UC_ARM_REG_PC) | 1, FLASH_SIZE, count=max_instructions)
            except unicorn.UcError:
                pc = self.uc.reg_read(arm.UC_ARM_REG_PC)
                if pc == END_OF_EXECUTION:
                    returns = self.protos_by_name[prototype.func].returns
                    value = self.uc.reg_read(arm.UC_ARM_REG_R0)
                    LOG.debug("execution complete (return=%s)", returns.decode(value))
                    return returns.get_python(value)
                elif pc in self.patches_by_addr:
                    patch = self.patches_by_addr[pc]
                    LOG.debug("entering patch %r", patch)
                    prototype = patch.prototype
                    args = prototype.get_args(self)
                    getattr(self.mocks, prototype.func)(*args)
                    patch.execute(self, *args)
                    self.uc.reg_write(arm.UC_ARM_REG_PC, self.uc.reg_read(arm.UC_ARM_REG_LR))
                else:
                    LOG.debug("exception raised at pc=%08x", pc)
                    raise
            else:
                LOG.debug("maximum instructions executed")
                break

    def set_func_proto(self, func, *args, **kwargs):
        program = self
        prototype = Prototype(self, func, self.funcs_by_name[func].addr, *args, **kwargs)
        self.protos_by_name[func] = prototype

        class CallerClass(object):
            def __init__(self):
                self.mock = None

            def __call__(self, *args, **kwargs):
                return program.run(prototype, *args, **kwargs)

            def patch(self, mock):
                self.mock = mock
                program.patches_by_addr[prototype.addr] = patch = Patch(prototype, mock)

                # Replace mocked function with bkpt #0 0xbe00
                patch.restore_instr = str(program.uc.mem_read(prototype.addr, 2))
                program.uc.mem_write(prototype.addr, "\x00\xbe")

                return mock

        return CallerClass()

    def unpatch_all(self):
        for addr, patch in self.patches_by_addr.iteritems():
            self.uc.mem_write(addr, patch.restore_instr)
        self.patches_by_addr = {}

    def alloc(self, size):
        addr = self.heap
        self.heap += size
        return addr
