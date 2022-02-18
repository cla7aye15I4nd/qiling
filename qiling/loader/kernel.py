#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .loader import QlLoader


class QlLoaderKERNEL(QlLoader):
    def __init__(self, ql):
        super().__init__(ql)

    def run(self):
        pass
