import gvars
from defines import gevs


class Operand:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "0x{:02X}".format(self.value)


class IndexedOperand:
    def __init__(self, variable: Operand, index: Operand):
        self.variable = variable
        self.index = index

    def __str__(self):
        return "{}({})".format(self.variable, self.index)


class LiteralOperand(Operand):
    def __str__(self):
        res = ""
        for i in self.value:
            if type(i) == str:
                i = ord(i)

            if 0x20 <= i <= 0x7E:
                res += chr(i)
            else:
                res += "\\x{:02x}".format(i)
        return "'{}'".format(res)


class IndexOperandValue(Operand):
    def __str__(self):
        if 9 <= self.value <= 16:
            return "I{}".format(int(self.value) - 8)
        elif 17 <= self.value <= 24:
            return "D{}".format(int(self.value) - 16)
        elif 25 <= self.value <= 33:
            return "P{}".format(int(self.value) - 25)
        elif 34 <= self.value <= 255:
            return "RDA{}".format(int(self.value) - 34)
            # return "RDA{}".format(int(self.value) - 33)
        else:
            return "0x{:x}".format(self.value)


class NumericOperand(Operand):
    def __str__(self):
        if 9 <= self.value <= 16:
            return "I{}".format(int(self.value) - 8)
        elif 17 <= self.value <= 24:
            return "D{}".format(int(self.value) - 16)
        elif 25 <= self.value <= 33:
            return "P{}".format(int(self.value) - 25)
        elif 34 <= self.value <= 191:
            return "RDA{}".format(int(self.value) - 34)
            # return "RDA{}".format(int(self.value) - 33)
        elif 192 <= self.value <= 255:
            return "&{}".format(int(self.value) - 191)
        elif 256 <= self.value <= 319:
            return "RDA{}".format(int(self.value) - 98)
            # return "RDA{}".format(int(self.value) - 97)
        elif 320 <= self.value <= 511:
            return "&{}".format(int(self.value) - 255)
        elif 0x200 <= self.value <= 0x7EFF:
            return gevs.get(self.value - 0x200 + 1, "#{}".format(self.value - 0x200 + 1))
        else:
            return "0x{:x}".format(self.value)


class OffsetOperand(Operand):
    def __init__(self, value):
        super(OffsetOperand, self).__init__(value)
        self.address = gvars.f.tell() - gvars.main_loc
        self.target = self.address + self.value

    def __str__(self):
        return "0x{:x}".format(self.value)
