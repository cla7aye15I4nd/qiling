#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.os import QlOs


class QlOsKernel(QlOs):
    def __init__(self, ql):
        super().__init__(ql)

    def run(self):
        count = self.ql.count
        end = self.ql.exit_point if self.ql.exit_point is not None else -1
        
        self.ql.emu_start(self.ql.arch.get_pc(), end, count=count)
