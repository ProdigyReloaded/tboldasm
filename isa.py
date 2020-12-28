# Copyright 2023, Phillip Heller
#
# This file is part of Prodigy Reloaded.
#
# Prodigy Reloaded is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# Prodigy Reloaded is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with Prodigy Reloaded. If not,
# see <https://www.gnu.org/licenses/>.

import math
import struct
from typing import Union

import bitstruct

from defines import gevs, functions, actions
from gvars import procedures, labels
import gvars

def handle_complex(b, operands):
    b.extend(gvars.f.read(1))
    if b[-2] & 0x80:
        b.extend(gvars.f.read(1))
        operands.append(IndexedOperand(
            NumericOperand(int.from_bytes(b[-3:-1], 'big') & 0x7fff),
            IndexOperandValue(int.from_bytes(b[-1:], 'big'))))
    else:
        operands.append(NumericOperand(struct.unpack(">h", b[-2:])[0]))

def handle_string(b, operands):
    b.extend(gvars.f.read(1))
    count = max(b[-1], 1)
    b.extend(gvars.f.read(b[1]))
    literal = b[count * -1:].decode('unicode_escape')
    operands.append(LiteralOperand(literal))


def handle_var_args(operand_count, is_complex, operand_mode, operands, instruction_bytes):
    for i in range(0, operand_count):
        b = bytearray(gvars.f.read(1))
        if is_complex and operand_mode[i] is True:
            handle_complex(b, operands)
        elif b[0] == 0x00:
            handle_string(b, operands)
        else:
            operands.append(NumericOperand(b[-1]))
        instruction_bytes.extend(b)


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
        # return repr(self.value)
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
            return "${}".format(int(self.value) - 33)
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
            return "${}".format(int(self.value) - 33)
        elif 192 <= self.value <= 255:
            return "&{}".format(int(self.value) - 191)
        elif 256 <= self.value <= 319:
            return "${}".format(int(self.value) - 97)
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


class Instruction:
    OPERANDS: int = 0
    OPCODE: bytes = b''
    MNEMONIC: str = ''
    COMPLEX_SHIFT: int = 0

    def __init__(self, instruction_bytes: bytearray, operands: list[Operand]):
        self.instruction_bytes = instruction_bytes
        self.operands = operands
        self.address = None

    def get_offset_operands(self) -> list[OffsetOperand]:
        return [o for o in self.operands if isinstance(o, OffsetOperand)]

    @classmethod
    def decode(cls, instr, is_complex):
        instruction_bytes = bytearray(instr)
        operands: list[Union[Operand, IndexedOperand]] = list()

        operand_mode = None
        if is_complex:
            # read the mode byte
            instruction_bytes.extend(gvars.f.read(1))
            operand_mode = bitstruct.unpack('b1b1b1b1b1b1b1b1', instruction_bytes[-1:])

        operand_count = cls.OPERANDS
        if operand_count == -1:
            instruction_bytes.extend(gvars.f.read(1))
            operand_count = instruction_bytes[-1]

        for i in range(0, operand_count):
            b = bytearray(gvars.f.read(1))
            if is_complex and operand_mode[i] is True:
                handle_complex(b, operands)
            elif b[0] == 0x00:
                # it's a string
                b.extend(gvars.f.read(1))
                count = b[-1]
                if count > 0:
                    b.extend(gvars.f.read(b[1]))
                    operands.append(LiteralOperand(b[count * -1:]))
                elif count == 0:
                    operands.append(LiteralOperand(''))
                else:
                    raise Exception('unexpected literal length')
            else:
                operands.append(NumericOperand(b[-1]))
            instruction_bytes.extend(b)

        return cls(instruction_bytes, operands)

    def __str__(self):
        return "{} {}".format(self.MNEMONIC, ', '.join([str(operand) for operand in self.operands])).rstrip() + ";"


class OffsetInstruction(Instruction):
    OPCODE = None
    OPERANDS = 0
    MNEMONIC = ""

    @classmethod
    def decode(cls, instr, is_complex):
        i = super(OffsetInstruction, cls).decode(instr, is_complex)
        i.instruction_bytes.extend(gvars.f.read(2))
        i.operands.append(OffsetOperand(struct.unpack('>h', i.instruction_bytes[-2:])[0]))
        return i

    def __str__(self):
        return "{} {}, {}".format(self.MNEMONIC, ', '.join([str(operand) for operand in self.operands[:-1]]),
                                   labels.get(self.operands[-1].value + self.address + len(self.instruction_bytes),
                                              "0x{:x}".format(self.operands[-1].value))).rstrip() + ";"


class Break(Instruction):
    OPCODE = b'\x00'
    OPERANDS = 0
    MNEMONIC = "BREAK"


class Cjeq(OffsetInstruction):
    OPCODE = b'\x01'
    OPERANDS = 2
    MNEMONIC = "CJEQ"


class Cjne(OffsetInstruction):
    OPCODE = b'\x02'
    OPERANDS = 2
    MNEMONIC = "CJNE"


class Cjlt(OffsetInstruction):
    OPCODE = b'\x03'
    OPERANDS = 2
    MNEMONIC = "CJLT"


class Cjgt(OffsetInstruction):
    OPCODE = b'\x04'
    OPERANDS = 2
    MNEMONIC = "CJGT"


class Cjle(OffsetInstruction):
    OPCODE = b'\x05'
    OPERANDS = 2
    MNEMONIC = "CJLE"


class Cjge(OffsetInstruction):
    OPCODE = b'\x06'
    OPERANDS = 2
    MNEMONIC = "CJGE"


class Jump(OffsetInstruction):
    OPCODE = b'\x07'
    OPERANDS = 0
    MNEMONIC = "JUMP"

    def __str__(self):
        return "JUMP {};".format(labels.get(self.operands[-1].value + self.address + len(self.instruction_bytes)),
                                 self.operands[-1].value)


class DefField(Instruction):
    OPCODE = b'\x08'
    OPERANDS = 5
    MNEMONIC = "DEFINE_FIELD"

    @classmethod
    def decode(cls, instr, is_complex):
        i = super(DefField, cls).decode(instr, is_complex)
        i.instruction_bytes.extend(gvars.f.read(1))
        i.operands.append(NumericOperand(int.from_bytes(i.instruction_bytes[-1:], 'big')))
        return i


class DefFieldPgm(Instruction):
    OPCODE = b'\x09'
    OPERANDS = 6
    MNEMONIC = "DEFINE_FIELD"

# TODO resolve the field constants
# 0x8000 - ACTION
# 0x4000 - DISPLAY
# 0x2000 - INPUT
# 0x0000 - ALPHANUMERIC
# 0x0080 - ALPHABETIC
# 0x0040 - NUMERIC
# 0x0020 - FORM
# 0x0010 - PASSWORD
#        - COLOR
# $95 = 128 = 0x80
# $31 = 64 = =0x40
# P7 = 32 = 0x20

class SetAtt(Instruction):
    OPCODE = b'\x0a'
    OPERANDS = 1
    MNEMONIC = "SET_ATTRIBUTE"

    @classmethod
    def decode(cls, instr, is_complex):
        i = super(SetAtt, cls).decode(instr, is_complex)
        # new_state
        i.instruction_bytes.extend(gvars.f.read(1))
        i.operands.append(Operand(i.instruction_bytes[-1]))
        # TODO this is actually two bytes; decode per the table above

        new_form = 0
        new_state = i.operands[-1].value
        if new_state & 0x10:
            # string operand follows with new form?
            b = bytearray(gvars.f.read(1))
            if b[0] == 0x00:
                # it's a string
                b.extend(gvars.f.read(1))
                count = max(b[-1], 1)
                b.extend(gvars.f.read(b[1]))
                i.operands.append(LiteralOperand(b[count * -1:]))
            else:
                i.operands.append(NumericOperand(b[-1]))
            i.instruction_bytes.extend(b)
        else:
            # new_form
            i.instruction_bytes.extend(gvars.f.read(1))
            i.operands.append(NumericOperand(i.instruction_bytes[-1]))
            new_form = i.instruction_bytes[-1]

        # new_foreground
        i.instruction_bytes.extend(gvars.f.read(1))
        i.operands.append(NumericOperand(i.instruction_bytes[-1]))

        # new_background
        i.instruction_bytes.extend(gvars.f.read(1))
        i.operands.append(NumericOperand(i.instruction_bytes[-1]))

        if new_form & 0x20:
            i.instruction_bytes.extend(gvars.f.read(1))
            count = i.instruction_bytes[-1]
            i.instruction_bytes.extend(gvars.f.read(count))
            literal = i.instruction_bytes[count * -1:].decode('unicode_escape')
            i.operands.append(LiteralOperand(literal))

        return i


class Open(Instruction):
    OPCODE = b'\x0b'
    OPERANDS = 2
    MNEMONIC = "OPEN"


class CloseAll(Instruction):
    OPCODE = b'\x0c'
    OPERANDS = 0
    MNEMONIC = "CLOSE"


class Close(Instruction):
    OPCODE = b'\x0d'
    OPERANDS = 1
    MNEMONIC = "CLOSE"


class Read(Instruction):
    OPCODE = b'\x0e'
    OPERANDS = 2
    MNEMONIC = "READ"


class ReadLine(Instruction):
    OPCODE = b'\x0f'
    OPERANDS = 3
    MNEMONIC = "READ_LINE"


class Write(Instruction):
    OPCODE = b'\x10'
    OPERANDS = 2
    MNEMONIC = "WRITE"


class WriteLine(Instruction):
    OPCODE = b'\x11'
    OPERANDS = 3
    MNEMONIC = "WRITE_LINE"


class Connect(Instruction):
    OPCODE = b'\x12'
    OPERANDS = 1
    MNEMONIC = "CONNECT"


class Disconnect(Instruction):
    OPCODE = b'\x13'
    OPERANDS = 0
    MNEMONIC = "DISCONNECT"


# Abstract for common decode bits
class Send(Instruction):
    @classmethod
    def decode(cls, instr, is_complex):
        i = super(Send, cls).decode(instr, is_complex)

        # Timeout; patent source shows it as big endian, but the values in 6.03.10 suggest little endian;
        # e.g, 0x2d00 and 0x3c00 = (11520, 15360) vs 0x002d, 0x003c = (45, 60)
        i.instruction_bytes.extend(gvars.f.read(2))
        i.operands.append(NumericOperand(struct.unpack('>h', i.instruction_bytes[-2:])[0]))

        # OptHdr
        i.instruction_bytes.extend(gvars.f.read(1))
        i.operands.append(NumericOperand(i.instruction_bytes[-1]))

        # TODO resolve the OptHdr values to mnemonics
        # hdrflag = OptHdr & OPTHDRMSK (0x2)
        # bpriority = OptHdr & PRIORITYMSK (0x4)

        return i


class SendNoId(Send):
    OPCODE = b'\x14'
    OPERANDS = 1
    MNEMONIC = "SEND"


class SendId(Send):
    OPCODE = b'\x15'
    OPERANDS = 2
    MNEMONIC = "SEND"


class Receive(Instruction):
    OPCODE = b'\x16'
    OPERANDS = 2
    MNEMONIC = "RECEIVE"


class Cancel(Instruction):
    OPCODE = b'\x17'
    OPERANDS = 1
    MNEMONIC = "CANCEL"


class Nav(Instruction):
    OPCODE = b'\x18'
    OPERANDS = 1
    MNEMONIC = "NAVIGATE"


class NavNext(Instruction):
    OPCODE = b'\x19'
    OPERANDS = 0
    MNEMONIC = "NAVIGATE NEXT"


class NavBack(Instruction):
    OPCODE = b'\x1a'
    OPERANDS = 0
    MNEMONIC = "NAVIGATE BACK"


class NavFirst(Instruction):
    OPCODE = b'\x1b'
    OPERANDS = 0
    MNEMONIC = "NAVIGATE FIRST"


class NavLast(Instruction):
    OPCODE = b'\x1c'
    OPERANDS = 0
    MNEMONIC = "NAVIGATE LAST"


class Fetch(Instruction):
    OPCODE = b'\x1d'
    OPERANDS = 1
    MNEMONIC = "FETCH"


class FetchRq(Instruction):
    OPCODE = b'\x1e'
    OPERANDS = 2
    MNEMONIC = "FETCH"


class OpenWindow(Instruction):
    OPCODE = b'\x1f'
    OPERANDS = 1
    MNEMONIC = "OPEN_WINDOW"


class OpenWindErr(Instruction):
    OPCODE = b'\x20'
    OPERANDS = 2
    MNEMONIC = "OPEN_ERROR_WINDOW"


class CloseWindow(Instruction):
    OPCODE = b'\x21'
    OPERANDS = 0
    MNEMONIC = "CLOSE_WINDOW"


class CloseOpenWindow(Instruction):
    OPCODE = b'\x22'
    OPERANDS = 1
    MNEMONIC = "CLOSE_WINDOW"
    # Think this opcode is disambiguated with the other CLOSE_WINDOW mnemonic by # of args


class Kill(Instruction):
    OPCODE = b'\x23'
    OPERANDS = 1
    MNEMONIC = "KILL"


class Purge(Instruction):
    OPCODE = b'\x24'
    OPERANDS = 0
    MNEMONIC = "PURGE"
    # TODO this might be "PURGE_CACHE" ?


class Move(Instruction):
    OPCODE = b'\x25'
    OPERANDS = 2
    MNEMONIC = "MOVE"

class MoveBlock(Instruction):
    OPCODE =b'\x62'
    OPERANDS = 3
    MNEMONIC = "MOVE"

class MoveAbs(Instruction):
    OPCODE = b'\x26'
    OPERANDS = 2
    MNEMONIC = "MOVE_ABS"

    def __str__(self):
        return "MOVE {}, {}, ABS;".format(self.operands[0], self.operands[1])


class Swap(Instruction):
    OPCODE = b'\x27'
    OPERANDS = 2
    MNEMONIC = "SWAP"


class Add(Instruction):
    OPCODE = b'\x28'
    OPERANDS = 2
    MNEMONIC = "ADD"


class Sub(Instruction):
    OPCODE = b'\x29'
    OPERANDS = 2
    MNEMONIC = "SUBTRACT"


class Mul(Instruction):
    OPCODE = b'\x2a'
    OPERANDS = 2
    MNEMONIC = "MULTIPLY"


class Div(Instruction):
    OPCODE = b'\x2b'
    OPERANDS = 2
    MNEMONIC = "DIVIDE"


class DivRem(Instruction):
    OPCODE = b'\x2c'
    OPERANDS = 3
    MNEMONIC = "DIVIDE"


class Fill(Instruction):
    OPCODE = b'\x2d'
    OPERANDS = 3
    MNEMONIC = "FILL"


class And(Instruction):
    OPCODE = b'\x2e'
    OPERANDS = 2
    MNEMONIC = "AND"


class Or(Instruction):
    OPCODE = b'\x2f'
    OPERANDS = 2
    MNEMONIC = "OR"


class Xor(Instruction):
    OPCODE = b'\x30'
    OPERANDS = 2
    MNEMONIC = "XOR"


class Test(Instruction):
    OPCODE = b'\x31'
    OPERANDS = 2
    MNEMONIC = "TEST"


class Length(Instruction):
    OPCODE = b'\x32'
    OPERANDS = 2
    MNEMONIC = "LENGTH"


class Format(Instruction):
    OPCODE = b'\x33'
    OPERANDS = 3
    MNEMONIC = "FORMAT"


class MakeFormat(Instruction):
    OPCODE = b'\x34'
    OPERANDS = -1
    MNEMONIC = "MAKE_FORMAT"

    @classmethod
    def decode(cls, instr, is_complex):
        instruction_bytes = bytearray(instr)
        operands: list[Union[Operand, IndexedOperand]] = list()

        operand_mode = list()
        if is_complex:
            # read the mode byte
            instruction_bytes.extend(gvars.f.read(1))
            operand_mode.extend(bitstruct.unpack('b1b1b1b1b1b1b1b1', instruction_bytes[-1:]))

        instruction_bytes.extend(gvars.f.read(1))
        operand_count = instruction_bytes[-1] * 3 + 1

        if is_complex:
            addoper = (operand_count - 8)
            if addoper < 0:
                is_complex = False
            else:
                addmode = math.ceil(addoper / 8)
                for i in range(addmode):
                    instruction_bytes.extend(gvars.f.read(1))
                    operand_mode.extend(bitstruct.unpack('b1b1b1b1b1b1b1b1', instruction_bytes[-1:]))

        handle_var_args(operand_count, is_complex, operand_mode, operands, instruction_bytes)

        return cls(instruction_bytes, operands)

    def __str__(self):
        res = "MAKE_FORMAT {}".format(self.operands[0])
        for i in range(1, len(self.operands), 3):
            res += ",\n  {}".format(self.operands[i])
            if self.operands[i + 2].value == '\x00':
                res += ":{:n}".format(int(self.operands[i + 1].value))
            else:
                res += "::{:n}".format(int(self.operands[i + 2].value))
        res += ";"
        return res


class Edit(Instruction):
    OPCODE = b'\x35'
    OPERANDS = -1
    MNEMONIC = "EDIT"


class String(Instruction):
    OPCODE = b'\x36'
    OPERANDS = -1
    MNEMONIC = "STRING"


class Substr(Instruction):
    OPCODE = b'\x37'
    OPERANDS = 4
    MNEMONIC = "SUBSTR"


class Instr(Instruction):
    OPCODE = b'\x38'
    OPERANDS = 3
    MNEMONIC = "INSTR"


class Upper(Instruction):
    OPCODE = b'\x39'
    OPERANDS = 1
    MNEMONIC = "UPPERCASE"


class Push(Instruction):
    OPCODE = b'\x3a'
    OPERANDS = 1
    MNEMONIC = "PUSH"


class Pop(Instruction):
    OPCODE = b'\x3b'
    OPERANDS = 1
    MNEMONIC = "POP"


class SyncSave(Instruction):
    OPCODE = b'\x3c'
    OPERANDS = 1
    MNEMONIC = "SYNC_SAVE"


class SyncRel(Instruction):
    OPCODE = b'\x3d'
    OPERANDS = 1
    MNEMONIC = "SYNC_RELEASE"


class Timer(Instruction):
    OPCODE = b'\x3e'
    OPERANDS = 1
    MNEMONIC = "TIMER"
    # TODO TBOL.EXE has "TIMER_ON" and "TIMER_OFF"


class Wait(Instruction):
    OPCODE = b'\x3f'
    OPERANDS = 0
    MNEMONIC = "WAIT"


class Start(Instruction):
    """
    Looks like this wasn't well-defined at the time of the patent.  Looking at the binaries, though, I commonly see
    the pattern '40 00 80 80'

    For now, we'll just read the instruction and then 3 bytes
    """
    OPCODE = b'\x40'
    OPERANDS = 0
    MNEMONIC = "START"

    @classmethod
    def decode(cls, instr, is_complex):
        instruction_bytes = bytearray(instr)
        operands: list[Operand] = list()

        instruction_bytes.extend(gvars.f.read(3))
        for i in range(3):
            operands.append(NumericOperand(instruction_bytes[-1 * i]))

        return cls(instruction_bytes, operands)


class Stop(Instruction):
    OPCODE = b'\x41'
    OPERANDS = 1
    MNEMONIC = "STOP"


class SetKey(Instruction):
    OPCODE = b'\x42'
    OPERANDS = 3
    MNEMONIC = "SET_KEY"


class SetKeyPrg(Instruction):
    OPCODE = b'\x43'
    OPERANDS = 5
    MNEMONIC = "SET_KEY"
    # think disambiguated between opcodes by arg count


class SetFunc(Instruction):
    OPCODE = b'\x44'
    OPERANDS = 2
    MNEMONIC = "SET_FUNCTION"

    def __str__(self):
        # TODO rewrite the __str__ that deal with function and action; maybe figure out a better inheritance here for
        #   code reuse
        # TODO sometimes this resolves things improperly.  E.g., an operand might actually mean register P7,
        #   but that is being resolved to whatever P7's memory address is, within the defined functions table
        function = self.operands[0]
        if isinstance(function, NumericOperand):
            function = functions.get(int(function.value), int(function.value))
        elif isinstance(function, LiteralOperand):
            function = function.value.decode('ascii')
            if function.isnumeric():
                function = functions.get(int(function), int(function))

        action = self.operands[1]
        if isinstance(action, NumericOperand):
            action = int(action.value)
        elif isinstance(action, LiteralOperand):
            action = action.value.decode('ascii')
            action = action.isnumeric() and int(action) or action

        return "{} {}, {};".format(self.MNEMONIC,
                                   function,
                                   actions.get(action, action)
                                   )


class SetFuncPgm(Instruction):
    OPCODE = b'\x45'
    OPERANDS = 3
    MNEMONIC = "SET_FUNCTION"

    def __str__(self):
        function = self.operands[0]
        if isinstance(function, NumericOperand):
            function = int(function.value)
        elif isinstance(function, LiteralOperand):
            function = function.value.decode('ascii')
        action = self.operands[1]
        if isinstance(action, NumericOperand):
            action = int(action.value)
        elif isinstance(action, LiteralOperand):
            action = action.value.decode('ascii')
            action = action.isnumeric() and int(action) or action

        return "{} {}, {}, {};".format(self.MNEMONIC,
                                       functions.get(int(function), function),
                                       actions.get(action, action),
                                       self.operands[2]
                                       )


class Call(OffsetInstruction):
    OPCODE = b'\x46'
    OPERANDS = -1
    MNEMONIC = "CALL"

    def __str__(self):
        res = "{}".format(procedures[self.address + int(self.operands[-1].value) + len(self.instruction_bytes)])
        if len(self.operands) > 1:
            res += " "
            res += ", ".join([str(o) for o in self.operands[:-1]])
        return res + ";"


class Link(Instruction):
    OPCODE = b'\x47'
    OPERANDS = -1
    MNEMONIC = "LINK"


class Return(Instruction):
    OPCODE = b'\x48'
    OPERANDS = 0
    MNEMONIC = "RETURN"


#     189  C9 30 04 49 3B 80 1A 1C                  label_17:  TRANSFER $41, $27, 0x801a1c, SYS_CURRENT_CURSOR_POS;
#          02 19
# this 3 byte operand gets disassembled improperly
class Transfer(Instruction):
    OPCODE = b'\x49'
    OPERANDS = 2
    MNEMONIC = "TRANSFER"

    @classmethod
    def decode(cls, instr, is_complex):
        instruction_bytes = bytearray(instr)
        operands: list[Operand] = list()

        operand_mode = None
        if is_complex:
            # read the mode byte
            instruction_bytes.extend(gvars.f.read(1))
            operand_mode = bitstruct.unpack('b1b1b1b1b1b1b1b1', instruction_bytes[-1:])

        instruction_bytes.extend(gvars.f.read(1))
        operand_count = instruction_bytes[-1]

        handle_var_args(operand_count, is_complex, operand_mode, operands, instruction_bytes)

        return cls(instruction_bytes, operands)


class Exit(Instruction):
    OPCODE = b'\x4a'
    OPERANDS = 0
    MNEMONIC = "EXIT"


class GoDep(Instruction):
    OPCODE = b'\x4b'
    OPERANDS = 2
    MNEMONIC = "GOTO_DEPENDING_ON"

    @classmethod
    def decode(cls, instr, is_complex):
        i = super(GoDep, cls).decode(instr, is_complex)
        for count in range(i.instruction_bytes[-1]):
            i.instruction_bytes.extend(gvars.f.read(2))
            i.operands.append(OffsetOperand(struct.unpack('>h', i.instruction_bytes[-2:])[0]))

        return i

    def __str__(self):
        res = "GOTO_DEPENDING_ON {}, ".format(self.operands[0])
        res += ", ".join([labels.get(i.target, str(i)) for i in self.get_offset_operands()])
        res += ";"
        return res


class Error(Instruction):
    OPCODE = b'\x4c'
    OPERANDS = 1
    MNEMONIC = "ERROR"


class SaveField(Instruction):
    OPCODE = b'\x4d'
    OPERANDS = 2
    #MNEMONIC = "SAVE!"
    MNEMONIC = "SAVE"
    # think this is disambiguated by # or args

    # Number of Fields, Block Name, first field
    # seems mode byte applies to operands following the number of fields
    # TODO this is hacky, fix it
    @classmethod
    def decode(cls, instr, is_complex):
        instruction_bytes = bytearray(instr)
        operands: list[Union[Operand, IndexedOperand]] = list()

        operand_mode = None
        if is_complex:
            # read the mode byte
            instruction_bytes.extend(gvars.f.read(1))
            operand_mode = bitstruct.unpack('b1b1b1b1b1b1b1b1', instruction_bytes[-1:])

        # read number of fields
        operand_count = cls.OPERANDS
        instruction_bytes.extend(gvars.f.read(1))
        operands.append(NumericOperand(struct.unpack("B", instruction_bytes[-1:])[0]))

        for i in range(0, operand_count):
            b = bytearray(gvars.f.read(1))
            if is_complex and operand_mode[i] is True:
                handle_complex(b, operands)
            elif b[0] == 0x00:
                # it's a string
                b.extend(gvars.f.read(1))
                count = max(b[-1], 1)
                b.extend(gvars.f.read(b[1]))
                operands.append(LiteralOperand(b[count * -1:]))
            else:
                operands.append(NumericOperand(b[-1]))
            instruction_bytes.extend(b)

        return cls(instruction_bytes, operands)


class SaveFields(Instruction):
    OPCODE = b'\x4e'
    OPERANDS = 3
    MNEMONIC = "SAVE"
    # Block name, first field, last field


class Restore(Instruction):
    OPCODE = b'\x4f'
    OPERANDS = 2
    MNEMONIC = "RESTORE"


class Release(Instruction):
    OPCODE = b'\x50'
    OPERANDS = 1
    MNEMONIC = "RELEASE"


class ClearField(Instruction):
    OPCODE = b'\x51'
    OPERANDS = 0
    MNEMONIC = "CLEAR"

    @classmethod
    def decode(cls, instr, is_complex):
        instruction_bytes = bytearray(instr)
        operands: list[Union[Operand, IndexedOperand]] = list()

        operand_mode = None
        if is_complex:
            # read the mode byte
            instruction_bytes.extend(gvars.f.read(1))
            operand_mode = bitstruct.unpack('b1b1b1b1b1b1b1b1', instruction_bytes[-1:])

        instruction_bytes.extend(gvars.f.read(1))

        b = bytearray(gvars.f.read(1))
        if is_complex and operand_mode[0] is True:
            handle_complex(b, operands)
        elif b[0] == 0x00:
            handle_string(b, operands)
        else:
            operands.append(NumericOperand(b[-1]))
        instruction_bytes.extend(b)

        return cls(instruction_bytes, operands)


class ClearFields(Instruction):
    OPCODE = b'\x52'
    OPERANDS = 2
    MNEMONIC = "CLEAR"


class Note(Instruction):
    OPCODE = b'\x53'
    OPERANDS = 2
    MNEMONIC = "NOTE"


class Point(Instruction):
    OPCODE = b'\x54'
    OPERANDS = 2
    MNEMONIC = "POINT"


class Sound(Instruction):
    OPCODE = b'\x55'
    OPERANDS = 0
    MNEMONIC = "SOUND"


class SetSound(Instruction):
    OPCODE = b'\x56'
    OPERANDS = 2
    MNEMONIC = "SOUND"


class Sort(Instruction):
    OPCODE = b'\x57'
    OPERANDS = 3
    MNEMONIC = "SORT"


class Lookup(Instruction):
    OPCODE = b'\x58'
    OPERANDS = 5
    MNEMONIC = "LOOKUP"


class SetBackGrnd(Instruction):
    OPCODE = b'\x59'
    OPERANDS = 1
    MNEMONIC = "SET_BACKGROUND"


class TrigFunc(Instruction):
    OPCODE = b'\x5a'
    OPERANDS = 1
    MNEMONIC = "TRIGGER_FUNCTION"

    def __str__(self):
        function = self.operands[0]
        if isinstance(function, NumericOperand):
            function = int(function.value)
        elif isinstance(function, LiteralOperand):
            function = function.value.decode('ascii')
            function = function.isnumeric() and int(function) or function

        return "{} {};".format(self.MNEMONIC, functions.get(function, function))


class FileScreen(Instruction):
    OPCODE = b'\x5b'
    OPERANDS = 1
    MNEMONIC = "FILE_SCREEN"


class ShowScreen(Instruction):
    OPCODE = b'\x5c'
    OPERANDS = 1
    MNEMONIC = "SHOW_SCREEN"


class Upload(Instruction):
    OPCODE = b'\x5d'
    OPERANDS = 2
    MNEMONIC = "UPLOAD"


class Download(Instruction):
    OPCODE = b'\x5e'
    OPERANDS = 2
    MNEMONIC = "DOWNLOAD"


class Access(Instruction):
    OPCODE = b'\x5f'
    OPERANDS = 2
    MNEMONIC = "ACCESS"


class ReturnRc(Instruction):
    OPCODE = b'\x63'
    OPERANDS = 1
    MNEMONIC = "RETURN"


class ExitRc(Instruction):
    OPCODE = b'\x64'
    OPERANDS = 1
    MNEMONIC = "EXIT"


class Refresh(Instruction):
    OPCODE = b'\x65'
    OPERANDS = 0
    MNEMONIC = "REFRESH"


class Erase(Instruction):
    OPCODE = b'\x66'
    OPERANDS = 1
    MNEMONIC = "ERASE"


class SetCursor(Instruction):
    OPCODE = b'\x67'
    OPERANDS = 1
    MNEMONIC = "SET_CURSOR"


class OpenErrWin(Instruction):
    OPCODE = b'\x6a'
    OPERANDS = 1
    MNEMONIC = "OPEN_ERROR_WINDOW"
    # TODO think this is disambiguated by arg count


class SetFuncPgm2(Instruction):
    OPCODE = b'\x6c'
    OPERANDS = 4
    MNEMONIC = "SET_FUNCTION"

    def __str__(self):
        function = self.operands[0]
        if isinstance(function, NumericOperand):
            function = int(function.value)
        elif isinstance(function, LiteralOperand):
            function = function.value.decode('ascii')
        action = self.operands[1]
        if isinstance(action, NumericOperand):
            action = int(action.value)
        elif isinstance(action, LiteralOperand):
            action = action.value.decode('ascii')
            action = action.isnumeric() and int(action) or action

        return "{} {}, {}, {}, {};".format(self.MNEMONIC,
                                           functions.get(int(function), function),
                                           actions.get(action, action),
                                           self.operands[2],
                                           self.operands[3]
                                           )


class OpenErrWin2(Instruction):
    OPCODE = b'\x6d'
    OPERANDS = 2                    # Confirmed with RSD debugger
    MNEMONIC = "OPEN_ERROR_WINDOW"


class DefFieldPgm2(Instruction):
    OPCODE = 0x6b
    # TODO this might be wrong; the Patent source says 7 arguments for this one
    OPERANDS = 4
    MNEMONIC = "DEF_FIELD_PGM2"


class Unknown(Instruction):
    OPCODE = b'\x70'
    OPERANDS = 0
    MNEMONIC = "UNKNOWN"


class DeleteFile(Instruction):
    OPCODE = b'\x6e'
    OPERANDS = 1
    MNEMONIC = "DELETEFILE"
    # unsupported in the version of TBOL.EXE discovered
