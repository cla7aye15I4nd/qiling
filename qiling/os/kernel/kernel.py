#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.os import QlOs


class QlOsKernel(QlOs):
    def __init__(self, ql):
        super().__init__(ql)

    def run(self):
        pass
