import logging
import unicorn.arm_const as arm

LOG = logging.getLogger(__name__)


class Unsigned16(object):
    def __init__(self, name=None):
        self.name = name

    def decode(self, value):
        return str(value)

    def return_value(self, value, program):
        program.uc.reg_write(arm.UC_ARM_REG_R0, value)


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

    def log_entry(self, program, return_value=None):
        params = ", ".join(param.decode(program) for param in self.params)
        if return_value is None:
            LOG.info("entered %s(%s)", self.func, params)
        else:
            LOG.info("%s(%s) => %s", self.func, params, self.returns.decode(return_value))

    def return_value(self, value, program):
        self.returns.return_value(value, program)
