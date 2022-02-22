from angr import SimState
from copy import deepcopy
from capstone.arm import *

class StateWrapper:
    def __init__(self, skye, state: "SimState", path=[], last_position=0):
        self.path = path
        self.skye = skye
        self.state = state
        self.last_position = last_position

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
            lhs, rhs = ins.op_str.split(',', maxsplit=1)
            
            rhs = rhs.strip('[ ]')
            reg, offset = rhs, 0
            if '#' in rhs:
                reg, num = rhs.split(', #')
                offset = int(num, 16)

            if reg != 'pc':
                address = getattr(self.state.regs, reg).args[0] + offset
                hw = self.skye.emulator.hw.find(address)
                
                if hw is not None:
                    label = hw.label
                    field = hw.field_description(address - hw.base, 4)

                    if ins.mnemonic == 'str':
                        value = getattr(self.state.regs, lhs)
                        print(f'[{hex(self.state.addr)}] Store {label}.{field} = {value.args[0]}')
                        return [(ins, label, field, value)]

                    else: # ins.mnemonic == 'ldr':
                        sym = self.skye.symbol_manager.new_symbol(label, field,
                            { 
                                'path': [_ for _ in self.path] 
                            }
                        )

                        print(f'[{hex(self.state.addr)}] Put symbol "{sym.args[0]}" at {hex(address)}')
                        print(f'[{hex(self.state.addr)}] Load {label}.{field}')
                        self.state.memory.store(address, sym)
                        return [(ins, label, field, 0)]
        
        return []
        
    def step(self):
        if self.state.solver.constraints:
            self.state.solver.simplify()
            self.path.append([
                constraint for constraint in 
                self.state.solver.constraints[self.last_position:]
            ])
            self.last_position = len(self.state.solver.constraints)
            self.state.solver.constraints.clear()

        base = self.addr & ~1
        tmp = self.skye.emulator.mem.read(base, 4)
        
        ins = next(self.skye.disassembler.disasm(tmp, base))
        extra = self.parse(ins)

        return [
            StateWrapper(self.skye, state, self.path + extra, self.last_position)
            for state in self.state.step(num_inst=1).successors
        ]

    def show_path(self):
        print('[PATH BEGIN]')
        for node in self.path:
            if type(node) is tuple:
                ins, label, field, value = node
                if ins.mnemonic == 'str':
                    print(f'[W] {label}.{field} = {value}')
                
                else:
                    print(f'[R] {label}.{field}')
            
            elif type(node) is list:
                print(f'[C] {node}')
        print('[PATH END]')


    @property
    def addr(self):
        return self.state.addr

    def __str__(self):
        return str(self.state)
