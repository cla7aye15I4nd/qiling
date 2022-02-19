#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.os import QlOs


class QlOsKernel(QlOs):
    def __init__(self, ql):
        super().__init__(ql)

    def run(self):
        if self.ql.exit_point:
            self.exit_point = self.ql.exit_point
        
        self.ql.emu_start(self.ql.arch.get_pc(), self.exit_point, count=self.ql.count)
