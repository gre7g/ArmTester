#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

# from __future__ import print_function
import logging
import unicorn
import unicorn.arm_const as arm

from arm_program import Program

DISASSEMBLY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\with_source.lst"
BINARY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\SnapEFR32MG12.bin"
STACK_START = 0x20001000
DEBUG_FUNC = "random12"

LOG = logging.getLogger(__name__)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    LOG.info("Emulate THUMB code")
    program = Program(DISASSEMBLY, BINARY)
    program.set_sp(STACK_START)
    program.start(DEBUG_FUNC)
    for i in xrange(10):
        program.step()
    LOG.info("Emulation done")
