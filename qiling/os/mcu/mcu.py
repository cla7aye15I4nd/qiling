#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError, UC_ERR_OK

from qiling.os.os import QlOs
from qiling.arch.arm import QlArchARM
from qiling.extensions.multitask import MultiTaskUnicorn, UnicornTask


class QlOsMcuThread(UnicornTask):
    def __init__(self, ql: "Qiling", begin: int, end: int, task_id=None):
        super().__init__(ql.uc, begin, end, task_id)
        self.ql = ql
    
    def on_start(self):
        return None
    
    def on_interrupted(self, ucerr: int):
        self._begin = self.pc

        # And don't restore anything.
        if ucerr != UC_ERR_OK:
            raise UcError(ucerr)

        self.ql.hw.step()

class QlOsMcu(QlOs):
    def __init__(self, ql):
        super(QlOsMcu, self).__init__(ql)

        self.runable = True

    def stop(self):
        self.ql.emu_stop()
        self.runable = False

    def run(self):
        self.runable = True
        
        count = self.ql.count or 0
        end = self.ql.exit_point or -1

        utk = QlOsMcuThread(self.ql, self.ql.arch.effective_pc, end)
        self.ql.uc.task_create(utk)
        self.ql.uc.tasks_start(count=count)
