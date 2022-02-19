#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import lief

from .loader import QlLoader


class QlLoaderKERNEL(QlLoader):
    def __init__(self, ql):
        super().__init__(ql)

        self.elf = lief.parse(ql.path)

    @property
    def entry_point(self):
        return self.elf.entrypoint

    def run(self):
        self.ql.reg.pc = self.entry_point

        for segment in self.elf.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                self.ql.mem.map(segment.virtual_address, 0x80000000)            
                self.ql.mem.write(segment.virtual_address, bytes(segment.content))
