#!/usr/bin/env python3

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

import argparse
from argparse import RawTextHelpFormatter

import sys
import re
import textwrap

from isa import *

import bitstruct as bitstruct
from columnar import columnar
import gvars

# TODO build this table by reflection on all descendants of Instruction
opcodes = {
    0x00: Break,
    0x01: Cjeq,
    0x02: Cjne,
    0x03: Cjlt,
    0x04: Cjgt,
    0x05: Cjle,
    0x06: Cjge,
    0x07: Jump,
    0x08: DefField,
    0x09: DefFieldPgm,
    0x0a: SetAtt,
    0x0b: Open,
    0x0c: CloseAll,
    0x0d: Close,
    0x0e: Read,
    0x0f: ReadLine,
    0x10: Write,
    0x11: WriteLine,
    0x12: Connect,
    0x13: Disconnect,
    0x14: SendNoId,
    0x15: SendId,
    0x16: Receive,
    0x17: Cancel,
    0x18: Nav,
    0x19: NavNext,              # unimplemented in patent source
    0x1a: NavBack,              # unimplemented in patent source
    0x1b: NavFirst,             # unimplemented in patent source
    0x1c: NavLast,              # unimplemented in patent source
    0x1d: Fetch,
    0x1e: FetchRq,
    0x1f: OpenWindow,
    0x20: OpenWindErr,
    0x21: CloseWindow,
    0x22: CloseOpenWindow,
    0x23: Kill,
    0x24: Purge,
    0x25: Move,
    0x26: MoveAbs,
    0x27: Swap,
    0x28: Add,
    0x29: Sub,
    0x2a: Mul,
    0x2b: Div,
    0x2c: DivRem,
    0x2d: Fill,
    0x2e: And,
    0x2f: Or,
    0x30: Xor,
    0x31: Test,
    0x32: Length,
    0x33: Format,
    0x34: MakeFormat,
    0x35: Edit,
    0x36: String,
    0x37: Substr,
    0x38: Instr,
    0x39: Upper,
    0x40: Start,
    0x3a: Push,
    0x3b: Pop,
    0x3c: SyncSave,
    0x3d: SyncRel,
    0x3e: Timer,
    0x3f: Wait,
    # 0x40: Start,        # Unimplemented in patent source
    0x41: Stop,
    # 0x42: SetKey,
    0x43: SetKeyPrg,
    0x44: SetFunc,
    0x45: SetFuncPgm,
    0x46: Call,
    0x47: Link,
    0x48: Return,
    0x49: Transfer,
    0x4a: Exit,
    0x4b: GoDep,
    0x4c: Error,
    0x4d: SaveField,
    0x4e: SaveFields,
    0x4f: Restore,
    0x50: Release,
    0x51: ClearField,
    0x52: ClearFields,
    0x53: Note,
    0x54: Point,
    0x55: Sound,
    0x56: SetSound,
    0x57: Sort,
    0x58: Lookup,
    # 0x59: SetBackGrnd,
    0x5a: TrigFunc,
    0x5b: FileScreen,       # just a placeholder in the patent source
    0x5c: ShowScreen,
    0x5d: Upload,
    0x5e: Download,
    # 0x5f: Access,
    # 0x60:
    # 0x61:
    0x62: MoveBlock,
    0x63: ReturnRc,
    0x64: ExitRc,
    0x65: Refresh,
    0x66: Erase,
    0x67: SetCursor,
    # 0x68:
    # 0x69:
    0x6a: OpenErrWin,
    0x6b: DefFieldPgm2,
    0x6c: SetFunc2,
    0x6d: OpenErrWin2,
    0x6e: DeleteFile

    ### TODO these seem like instructions but aren't known; need to look for the "PROCOP" table in the binary to be sure
    # 0x70: Unknown
}


def procedure_name_maker():
    yield "main"
    i = 1
    while True:
        yield "proc_{}".format(i)
        i += 1

procedure_name = procedure_name_maker()


def label_name_maker():
    i = 1
    while True:
        yield "label_{}".format(i)
        i += 1

label_name = label_name_maker()

class Program:
    def __init__(self, args):
        self.args = args
        self.name: str = ""
        self.when: str = ""
        self.version: str = ""
        self.main_loc: int = 0
        self.instructions: dict[int, Instruction] = dict()

    def disassemble(self):
        gvars.f = f = self.args.infile

        if self.args.segment_offset != 0:
            f.seek(self.args.segment_offset)
            segtype, seglen, subtype = struct.unpack('<BhB', f.read(4))
            if segtype != 0x61:
                print("Wrong segment type (expected 0x61, got {})".format(hex(segtype)))
                sys.exit(-1)
            if subtype != 0x1:
                print("Not TBOL code")
                sys.exit(-1)

        f.seek(self.args.name_offset)

        namelen = struct.unpack('>h', f.read(2))[0]
        if namelen == 8:
            self.name = f.read(namelen).decode('unicode_escape')
            self.when = f.read(15).decode('unicode_escape')
            self.version = f.read(5).decode('unicode_escape')
            if not re.match('[0-9]{2}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}', self.when):
                self.when = "unknown"
                self.version = "unknown"
                f.seek(self.args.name_offset + 10)
        else:
            self.when = "unknown"
            self.version = "unknown"
            f.seek(self.args.name_offset + 1)

        self.main_loc = f.tell()
        gvars.main_loc = self.main_loc

        address = f.tell() - self.main_loc
        procedures[address] = next(procedure_name)
        while True:
            # read a byte to pass off to instruction decoder

            address = f.tell() - self.main_loc
            instr = f.read(1)
            if instr == b'':
                break
            is_complex, opcode = bitstruct.unpack('b1u7', instr)

            if opcode not in opcodes:
                raise Exception('Unhandled Opcode 0x{:x} at {:x}'.format(opcode, f.tell()))
            else:
                # decode the instruction and store the address for resolving calls, jumps, etc
                # TODO would be better to pass the address into the opcode decoder
                self.instructions[address] = opcodes[opcode].decode(instr, is_complex, f)
                self.instructions[address].address = address

                # all call / jump targets to respective tables
                if isinstance(self.instructions[address], Call):
                    offset = int(self.instructions[address].operands[-1].value)
                    target = offset + f.tell() - self.main_loc

                    if offset == 0:
                        procedures[target] = None
                    else:
                        if target not in procedures:
                            procedures[target] = next(procedure_name)
                elif isinstance(self.instructions[address], OffsetInstruction):
                    target = int(self.instructions[address].operands[-1].value) + f.tell() - self.main_loc
                    if target not in labels:
                        labels[target] = next(label_name)
                elif isinstance(self.instructions[address], GoDep):
                    for i in self.instructions[address].operands:
                        if isinstance(i, OffsetOperand) and i.target not in labels:
                            labels[i.target] = next(label_name)

    def print(self):
        out = self.args.outfile.write

        out("{{ Program {} compiled with TBOL COMPILER version {} }}\n".format(repr(self.name), self.version))
        out("{{ Date Program compiled {} }}\n\n".format(self.when))
        out("PROGRAM {};\n\n".format(self.name))
        instruction_list = list(self.instructions.items())
        if self.args.tabular:
            data = list()
            for addr, instruction in instruction_list:
                row = ["{:02X}".format(addr), format_instr(instruction.instruction_bytes), get_proc(addr), get_label(addr),
                      str(instruction)]
                data.append(row)

            table = columnar(data, ("addr", "bytes", "procedure", "label", "instruction"),
                             justify=['r', 'l', 'r', 'r', 'l'], no_borders=True, wrap_max=1000, terminal_width=200)
            out(table)
        else:
            for addr, instruction in instruction_list:
                proc = get_proc(addr)
                if proc:
                    if proc != "PROC main =":
                        out("END_PROC\n\n")
                    out(proc + "\n")
                label = get_label(addr)
                if label:
                    out("  " + label + "\n")
                out("    " + str(instruction) + "\n")
            out("END_PROC\n\n")

def get_proc(addr):
    proc = procedures.get(addr, None)
    if proc is not None:
        return "PROC {} =".format(proc)
    else:
        return ""

def get_label(addr):
    label = labels.get(addr, None)
    if label is not None:
        return "{}:".format(label)
    else:
        return ""



def format_instr(_bytes):
    return '\n'.join(' '.join('{:02X}'.format(b) for b in _bytes[i:i+8]) for i in range(0, len(_bytes), 8))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='tboldasm',
        formatter_class=RawTextHelpFormatter,
        description=textwrap.dedent(
            """
            A disassembler for Prodigy TBOL binaries.
            
            By default, tboldasm expects a TBOL binary as would be extracted from a STAGE.DAT file
            and encapsulated within a Program Segment (type 0x61), which itself is further
            encapsulated within an Object.
            
            The TBOL compiler, however, produces output that is un-encapsulated.  In order to
            disassemble such a file, it is necessary to inform the disassembler that there is no
            segment, and the proper location of the program name as included by the compiler.
            
            For most TBOL produced output ("ending in .COD"), this is done like so:
            
            % tboldasm -so 0 -no 4 PROGRAM.COD
            
            By default, tboldasm will print the decoded instructions in a format most closely resembling the
            input that was given to the TBOL compiler.  Notable exceptions are that branching instructions are
            not reversed to high level TBOL control structures or relevant boolean expressions.
            
            The "tabular" format is selected with the "--tabular" or "-t" argument, and looks something like this:
            
              ADDR  BYTES                       PROCEDURE     LABEL  INSTRUCTION                                  
    
                00  82 80 02 19 00 02 31 30   PROC main =            CJNE SYS_CURRENT_CURSOR_POS, '10', label_1;  
                    00 05 
            
            This format is most useful for diagnosing problems in the disassembly itself, as the decoded bytes
            are shown.
            
            """
        )
    )

    # can't default infile to sys.stdin because FileType 'rb' is ignored
    # https://bugs.python.org/issue14156
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='A binary input file containing TBOL instructions')
    parser.add_argument('-o', '--outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout,
                        help='A file to which the output is written (STDOUT).')
    parser.add_argument('-so', '--segment-offset', action='store', type=int, default=18,
                        help='The offset in the input where the segment header begins (16).')
    parser.add_argument('-no', '--name-offset', action='store', type=int, default=26,
                        help='The offset in the input where the program name begins (26)')
    parser.add_argument('-t', '--tabular', action='store_true', default=False,
                        help='Output the TBOL instructions in a tabular format including the raw bytes.')

    args = parser.parse_args()

    program = Program(args)

    try:
        program.disassemble()
    except Exception as e:
        print(e)
        print("0x{:x}".format(gvars.f.tell()))

    program.print()