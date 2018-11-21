import logging
import struct
import re
import unicorn.arm_const as arm

FILENAME = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\with_source.lst"
FUNCTION_BEGIN = re.compile(r"^([0-9a-f]{8}) <(\w+)>:")
LINE = re.compile(r"^\s+([0-9a-f]+):\s+([0-9a-f]+) ([0-9a-f]{4})?\s+\S+(.*)")
REGISTER_PORTION = re.compile(r"^\s+r(\d+),")

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


class Program(object):
    def __init__(self, filename, uc):
        self.funcs_by_name = {}
        self.inst_by_addr = {}
        self.register_to_log = None
        self.first_instruction = True
        self.uc = uc

        lines_before = ""
        with open(filename, "rt") as file_obj:
            while True:
                line = file_obj.readline()
                if not line:
                    break

                match = FUNCTION_BEGIN.search(line)
                if match:
                    function = Function(match)
                    if function.name not in self.funcs_by_name:
                        self.funcs_by_name[function.name] = function
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

            if self.register_to_log:
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

    def start(self, addr):
        self.uc.emu_start(addr | 1, 4, count=1)

    def step(self):
        self.first_instruction = True
        pc = self.uc.reg_read(arm.UC_ARM_REG_PC)
        self.uc.emu_start(pc | 1, 4, count=1)


def unhexlify(string):
    if string:
        value = int(string, 16)
        return struct.pack("<H" if len(string) == 4 else "<L", value)
    else:
        return ""


def extract_bin(listing):
    address = func_name = None
    binary = ""
    for line in listing.split("\n"):
        match = FUNCTION_BEGIN.search(line)
        if match:
            address, func_name = match.groups()
            # print int(address, 16), func_name
        else:
            match = LINE.search(line)
            if match:
                word1, word2 = match.groups()
                binary += unhexlify(word1) + unhexlify(word2)
    return int(address, 16), func_name, binary


if __name__ == "__main__":
    program = Program(FILENAME)
    print len(program.inst_by_addr), len(program.funcs_by_name)
#     address, func_name, binary = extract_bin("""
# 00015ee0 <initCrcDriver>:
#    15ee0:	b480      	push	{r7}
#    15ee2:	af00      	add	r7, sp, #0
#    15ee4:	4a0b      	ldr	r2, [pc, #44]	; (15f14 <initCrcDriver+0x34>)
#    15ee6:	4b0b      	ldr	r3, [pc, #44]	; (15f14 <initCrcDriver+0x34>)
#    15ee8:	f8d3 30b0 	ldr.w	r3, [r3, #176]	; 0xb0
#    15eec:	f043 0340 	orr.w	r3, r3, #64	; 0x40
#    15ef0:	f8c2 30b0 	str.w	r3, [r2, #176]	; 0xb0
#    15ef4:	4b08      	ldr	r3, [pc, #32]	; (15f18 <initCrcDriver+0x38>)
#    15ef6:	f240 1211 	movw	r2, #273	; 0x111
#    15efa:	601a      	str	r2, [r3, #0]
#    15efc:	4b06      	ldr	r3, [pc, #24]	; (15f18 <initCrcDriver+0x38>)
#    15efe:	f24a 0201 	movw	r2, #40961	; 0xa001
#    15f02:	60da      	str	r2, [r3, #12]
#    15f04:	4b04      	ldr	r3, [pc, #16]	; (15f18 <initCrcDriver+0x38>)
#    15f06:	2200      	movs	r2, #0
#    15f08:	609a      	str	r2, [r3, #8]
#    15f0a:	46bd      	mov	sp, r7
#    15f0c:	f85d 7b04 	ldr.w	r7, [sp], #4
#    15f10:	4770      	bx	lr
#    15f12:	bf00      	nop
#    15f14:	400e4000 	andmi	r4, lr, r0
#    15f18:	4001c000 	andmi	ip, r1, r0
# """)
#     print "0x%x %s %r" % (address, func_name, binary)
