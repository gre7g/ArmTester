#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

# from __future__ import print_function
import logging
import unicorn
import unicorn.arm_const as arm

from extract_bin import Program, FILENAME

# code to be emulated
# 0x15ee0 initCrcDriver '\x80\xb4\x00\xaf\x0bJ\x0bK\xd3\xf8\xb00C\xf0@\x03\xc2\xf8\xb00\x08K@\xf2\x11\x12\x1a`\x06KJ\xf2\x01\x02\xda`\x04K\x00"\x9a`\xbdF]\xf8\x04{pG\x00\xbf\x00@\x0e@\x00\xc0\x01@'
# THUMB_CODE = b'\x80\xb4\x00\xaf\x0bJ\x0bK\xd3\xf8\xb00C\xf0@\x03\xc2\xf8\xb00\x08K@\xf2\x11\x12\x1a`\x06KJ\xf2\x01\x02\xda`\x04K\x00"\x9a`\xbdF]\xf8\x04{pG\x00\xbf\x00@\x0e@\x00\xc0\x01@'
# memory address where emulation starts
# ADDRESS = 0x15ee0
FLASH_START = 0x00000000
FLASH_SIZE = 1024 * 1024
RAM_START = 0x20000000
RAM_SIZE = 128 * 1024
REGISTER_START = 0x40000000
REGISTER_SIZE = 0xe6400
STACK_START = 0x20001000
DEBUG_FUNC = "random12"

LOG = logging.getLogger(__name__)


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    tmp = uc.mem_read(address, size)
    print('>>> Instruction code at [0x%x] = %s' % (address, " ".join("%02x" % i for i in tmp)))
    print('r2=%08x r3=%08x r7=%08x' % (uc.reg_read(arm.UC_ARM_REG_R2), uc.reg_read(arm.UC_ARM_REG_R3), uc.reg_read(arm.UC_ARM_REG_R7)))
    return True


def test_thumb():
    LOG.info("Emulate THUMB code")
    # try:
    # Initialize emulator in thumb mode
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
    program = Program(FILENAME, uc)

    # map 2MB memory for this emulation
    uc.mem_map(FLASH_START, FLASH_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
    uc.mem_map(RAM_START, RAM_SIZE, unicorn.UC_PROT_ALL)
    uc.mem_map(REGISTER_START, REGISTER_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

    # write machine code to be emulated to memory
    with open(r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\SnapEFR32MG12.bin", "rb") as file_obj:
        uc.mem_write(FLASH_START, file_obj.read())

    # initialize machine registers
    uc.reg_write(arm.UC_ARM_REG_SP, STACK_START)

    # tracing all basic blocks with customized callback
    # uc.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)

    # tracing all instructions with customized callback
    uc.hook_add(unicorn.UC_HOOK_CODE, program.hook_code)

    # emulate machine code in infinite time
    # Note we start at ADDRESS | 1 to indicate THUMB mode.
    program.start(program.funcs_by_name[DEBUG_FUNC].addr)
    for i in xrange(10):
        program.step()

    # now print out some registers
    LOG.info("Emulation done")


    # except unicorn.UcError as e:
    #     print("ERROR: %s" % e)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # test_arm()
    # print("=" * 26)
    test_thumb()
