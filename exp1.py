import logging

from arm_program import Program

DISASSEMBLY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\with_source.lst"
BINARY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\SnapEFR32MG12.bin"
STACK_START = 0x20001000
DEBUG_FUNC = "random12"
BREAK_POINTS = ["randomBits"]

LOG = logging.getLogger(__name__)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    program = Program(DISASSEMBLY, BINARY)
    program.set_sp(STACK_START)
    program.set_breakpoints(BREAK_POINTS)
    program.run(DEBUG_FUNC)
