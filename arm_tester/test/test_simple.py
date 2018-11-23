import logging
from mock import Mock, call
from unittest import TestCase

from arm_tester.arm_program import Program
from arm_tester.types import Unsigned16, Unsigned8, PointerTo, Boolean

DISASSEMBLY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\with_source.lst"
BINARY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\SnapEFR32MG12.bin"
STACK_START = 0x20001000

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)


class TestSimple(TestCase):
    def setUp(self):
        self.vm = Program(DISASSEMBLY, BINARY)
        self.vm.set_sp(STACK_START)

    def tearDown(self):
        self.vm.flush_allocs()

    def test1(self):
        # U16 random12()
        random12 = self.vm.set_func_proto("random12", returns=Unsigned16())
        # U16 randomBits(U8 bits)
        randomBits = self.vm.set_func_proto("randomBits", Unsigned16("bits"), returns=Unsigned16())

        # TODO: add patch notation
        randomBits.patch(Mock(return_value=5))

        self.assertEqual(self.vm.functions.random12(), 5)
        randomBits.mock.assert_called_once_with(12)
        self.vm.mocks.assert_has_calls([call.randomBits(12)])

    # def test2(self):
    #     # void writeBit(U8 DECL_FASTRAM * bitset, U8 whichBit, Boolean value)
    #     writeBit = self.vm.set_func_proto("writeBit",
    #                                       PointerTo(Unsigned8("bitset")), Unsigned8("whichBit"), Boolean("value"))
