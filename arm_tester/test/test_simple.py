import logging
from mock import Mock, call
import unicorn.arm_const as arm
from unittest import TestCase

from arm_tester.arm_program import Program
from arm_tester.types import Unsigned16, Unsigned8, PointerTo, Boolean, Char, ArrayOf, Signed16

DISASSEMBLY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\with_source.lst"
BINARY = r"C:\synapse\insomnia\projects\core\Target\CoreARM\EFR32MG\workspace\SnapEFR32MG12\MGM12P_Debug\SnapEFR32MG12.bin"
STACK_START = 0x20001000
HEAP_START = 0x20002000

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)


class TestSimple(TestCase):
    # Class members:
    vm = None

    def setUp(self):
        if self.vm is None:
            TestSimple.vm = Program(DISASSEMBLY, BINARY)
        self.vm.set_sp(STACK_START)
        self.vm.set_heap(HEAP_START)

    def tearDown(self):
        self.vm.unpatch_all()

    def test_u16(self):
        # U16 random12()
        random12 = self.vm.set_func_proto("random12", returns=Unsigned16())
        # U16 randomBits(U8 bits)
        randomBits = self.vm.set_func_proto("randomBits", Unsigned16("bits"), returns=Unsigned16())

        # TODO: add patch notation
        randomBits.patch(Mock(return_value=5))

        self.assertEqual(random12(), 5)
        randomBits.mock.assert_called_once_with(12)
        self.vm.mocks.assert_has_calls([call.randomBits(12)])

    def test_pointer(self):
        # void writeBit(U8 DECL_FASTRAM * bitset, U8 whichBit, Boolean value)
        writeBit = self.vm.set_func_proto("writeBit",
                                          PointerTo(Unsigned8("bitset")), Unsigned8("whichBit"), Boolean("value"))

        memory = PointerTo(Unsigned8())
        memory.alloc(self.vm, 0x55)
        writeBit(memory, 3, True)
        writeBit(memory, 2, False)
        self.assertEqual(memory.read(self.vm), 0x59)

    def test_string(self):
        # char DECL_RAM *mystrrev(char DECL_RAM *head, char DECL_RAM *tail)
        mystrrev = self.vm.set_func_proto("mystrrev", PointerTo(Char("head")), PointerTo(Char("tail")),
                                          returns=PointerTo(Char()))
        # U8 s16toa(S16 _i, char DECL_RAM * const sbuf, U8 buflen)
        s16toa = self.vm.set_func_proto("s16toa", Signed16("_i"), PointerTo(Char("sbuf")), Unsigned8("buflen"),
                                        returns=Unsigned8())

        memory = PointerTo(ArrayOf(Char()))
        memory.alloc(self.vm, "1234567890")
        self.assertEqual(mystrrev(memory, memory + 9), memory)
        self.assertEqual(memory.read(self.vm), "0987654321")

        self.assertEqual(s16toa(0, memory, 11), 1)
        self.assertEqual(memory.read(self.vm, 1), "0")
        self.assertEqual(s16toa(32767, memory, 11), 5)
        self.assertEqual(memory.read(self.vm, 5), "32767")
        self.assertEqual(s16toa(-32768, memory, 11), 6)
        self.assertEqual(memory.read(self.vm, 6), "-32768")
