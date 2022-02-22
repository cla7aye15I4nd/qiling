from angr import SimState
from capstone.arm import *

class StateWrapper:
    def __init__(self, skye, state: "SimState", path=[]):
        self.path = path
        self.skye = skye
        self.state = state

    def copy(self, emulator):
        ## Copy memory
        for lbound, rbound, perm, label, is_mmio in emulator.mem.map_info:
            if not is_mmio:
                data = emulator.mem.read(lbound, rbound - lbound)
                self.state.memory.store(lbound, bytes(data))

        ## Copy Register
        reg_list = [
             "r0", "r1", "r2", "r3", "r4", 
             "r5", "r6", "r7", "r8", "r9", 
            "r10","r11","r12", "sp", "lr",
            "primask", "faultmask", "basepri", "control"
        ]
        for reg in reg_list:
            setattr(self.state.regs, reg, getattr(emulator.reg, reg))

    def parse(self, ins):
        if ins.mnemonic in {'ldr', 'str'}:
            dst, src = ins.op_str.split(',', maxsplit=1)
            
            src = src.strip('[ ]')
            reg, offset = src, 0
            if '#' in src:
                reg, num = src.split(', #')
                offset = int(num, 16)

            if reg != 'pc':
                address = getattr(self.state.regs, reg).args[0] + offset
                hw = self.skye.emulator.hw.find(address)
                print(hw)

        

    def step(self):
        extra = []

        base = self.addr & ~1
        tmp = self.skye.emulator.mem.read(base, 4)
        
        ins = next(self.skye.disassembler.disasm(tmp, base))
        self.parse(ins)

        return [
            StateWrapper(self.skye, state, self.path + extra)
            for state in self.state.step(num_inst=1).successors
        ]

    @property
    def addr(self):
        return self.state.addr

    def __str__(self):
        return str(self.state)
