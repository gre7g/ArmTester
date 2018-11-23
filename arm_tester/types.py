import logging
import struct
import unicorn.arm_const as arm

LOG = logging.getLogger(__name__)


class TypeClass(object):
    TEMPLATE = None

    def __init__(self, name=None):
        self.name = name

    def to_memory(self, value, uc, addr):
        uc.mem_write(addr, self.encode(value))

    def encode(self, value):
        return struct.pack(self.TEMPLATE, value)

    def get_length(self):
        return struct.calcsize(self.TEMPLATE)

    def from_memory(self, uc, addr):
        return struct.unpack(self.TEMPLATE, uc.mem_read(addr, self.get_length()))[0]

    def decode(self, value):
        return str(value)

    def get_python(self, value):
        return int(value)

    def value(self, value):
        return int(value)

    def return_value(self, value, program):
        program.uc.reg_write(arm.UC_ARM_REG_R0, value)

    def set_size(self, size):
        pass

    def set_addr(self, addr):
        pass


class Void(TypeClass):
    def value(self, value):
        return None


class Boolean(TypeClass):
    TEMPLATE = "?"


class Char(TypeClass):
    TEMPLATE = "B"

    def from_memory(self, uc, addr):
        return uc.mem_read(addr, 1)


class Unsigned8(TypeClass):
    TEMPLATE = "B"


class Unsigned16(TypeClass):
    TEMPLATE = "<H"


class Unsigned32(TypeClass):
    TEMPLATE = "<L"


class Signed8(TypeClass):
    TEMPLATE = "b"


class Signed16(TypeClass):
    TEMPLATE = "<h"


class Signed32(TypeClass):
    TEMPLATE = "<l"


class ZString(TypeClass):
    pass


class PString(TypeClass):
    pass


class PointerTo(TypeClass):
    def __init__(self, obj):
        TypeClass.__init__(self, None)
        self.obj = obj
        self.addr = None

    def alloc(self, program, value):
        string = self.obj.encode(value)
        self.obj.set_size(len(string))
        self.addr = program.alloc(len(string))
        self.obj.set_addr(self.addr)
        program.uc.mem_write(self.addr, string)

    def write(self, program, value):
        string = self.obj.encode(value)
        program.uc.mem_write(self.addr, string)

    def read(self, program):
        return self.obj.from_memory(program.uc, self.addr)

    def value(self, value):
        return value.addr

    def __add__(self, other):
        obj = PointerTo(self.obj)
        obj.addr = self.addr + other
        return obj


class ArrayOf(TypeClass):
    def __init__(self, obj):
        TypeClass.__init__(self, None)
        self.obj = obj
        self.count = 0
        self.addr = None

    def encode(self, value):
        return value + "\x00"

    def from_memory(self, uc, addr):
        if isinstance(self.obj, Char):
            return_value = ""
            for index in xrange(self.count):
                return_value += self.obj.from_memory(uc, self.addr + index)
                if "\x00" in return_value:
                    return_value = return_value[:return_value.index("\x00")]
        else:
            size_per = self.obj.get_length()
            return_value = []
            for index in xrange(self.count):
                return_value.append(self.obj.from_memory(uc, self.addr + index))

        return return_value

    def set_size(self, size):
        size_per = self.obj.get_length()
        assert (size % size_per) == 0, "Partial array element"
        self.count = size / size_per

    def get_length(self):
        return self.count * self.obj.get_length()

    def set_addr(self, addr):
        self.addr = addr



class EnumOf(TypeClass):
    pass


class StructOf(TypeClass):
    pass


class UnionOf(TypeClass):
    pass


class Parameter(object):
    def __init__(self, index, type_obj):
        self.index, self.type_obj = index, type_obj

    def decode(self, program):
        value = program.uc.reg_read(arm.UC_ARM_REG_R0 + self.index)  # TODO: maximum?
        return self.type_obj.decode(value)

    def set(self, program, value):
        program.uc.reg_write(arm.UC_ARM_REG_R0 + self.index, self.type_obj.value(value))

    def get_python(self, program):
        value = program.uc.reg_read(arm.UC_ARM_REG_R0 + self.index)  # TODO: maximum?
        return self.type_obj.get_python(value)


class Prototype(object):
    def __init__(self, program, func, addr, *args, **kwargs):
        self.program, self.func, self.addr = program, func, addr
        self.params = tuple(Parameter(index, arg) for index, arg in enumerate(args))
        self.returns = kwargs.get("returns") if "returns" in kwargs else Void()
        self.mock = None

    def log_entry(self, program, return_value=None):
        params = ", ".join(param.decode(program) for param in self.params)
        if return_value is None:
            LOG.info("entered %s(%s)", self.func, params)
        else:
            LOG.info("%s(%s) => %s", self.func, params, self.returns.decode(return_value))

    def return_value(self, value, program):
        self.returns.return_value(value, program)

    def get_args(self, program):
        return tuple(param.get_python(program) for param in self.params)

    def set_args(self, *args):
        assert len(args) == len(self.params), "wrong number of parameters for %r" % self
        for index, param in enumerate(self.params):
            param.set(self.program, args[index])
