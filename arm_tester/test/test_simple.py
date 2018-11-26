import logging
from mock import Mock, call
from unittest import TestCase

from arm_tester.arm_program import Program
from arm_tester.types import Unsigned16, Unsigned8, PointerTo, Boolean, Char, ArrayOf, Signed16

IGNORE_WORDS = ["DECL_FASTRAM", "DECL_RAM"]
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
            TestSimple.vm = Program(DISASSEMBLY, BINARY, IGNORE_WORDS)
        self.vm.set_sp(STACK_START)
        self.vm.set_heap(HEAP_START)

    def tearDown(self):
        self.vm.unpatch_all()

    def test_u16(self):
        random12 = self.vm.parse_proto("random12")
        randomBits = self.vm.parse_proto("randomBits")

        randomBits.patch(Mock(return_value=5))

        self.assertEqual(random12(), 5)
        randomBits.mock.assert_called_once_with(12)
        self.vm.mocks.assert_has_calls([call.randomBits(12)])

    def test_pointer(self):
        writeBit = self.vm.parse_proto("writeBit")

        memory = PointerTo(Unsigned8())
        memory.alloc(self.vm, 0x55)
        writeBit(memory, 3, True)
        writeBit(memory, 2, False)
        self.assertEqual(memory.read(self.vm), 0x59)

    def test_string(self):
        mystrrev = self.vm.parse_proto("mystrrev")

        memory = PointerTo(ArrayOf(Char()))
        memory.alloc(self.vm, "1234567890")
        self.assertEqual(mystrrev(memory, memory + 9), memory)
        self.assertEqual(memory.read(self.vm), "0987654321")

        s16toa = self.vm.parse_proto("s16toa")

        self.assertEqual(s16toa(0, memory, 11), 1)
        self.assertEqual(memory.read(self.vm, 1), "0")
        self.assertEqual(s16toa(32767, memory, 11), 5)
        self.assertEqual(memory.read(self.vm, 5), "32767")
        self.assertEqual(s16toa(-32768, memory, 11), 6)
        self.assertEqual(memory.read(self.vm, 6), "-32768")
