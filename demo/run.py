import sys
import angr
import claripy

sys.path.append('..')
from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.atmel import sam3x8e


def make_ql(path):
    ql = Qiling(
        [path],
        archtype="cortex_m", 
        ostype="mcu",
        env=sam3x8e, 
        verbose=QL_VERBOSE.DEFAULT
    )

    ql.hw.create('pmc').watch()
    return ql

def make_angr(path):
    return angr.Project(path, arch='ARMCortexM')

def make_state(proj, address):
    return proj.factory.blank_state(
        addr=address, 
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

def hook_read_register(proj, address):
    def put_symbol(state):
        sr = claripy.BVS(f'SR#{hex(address)[2:]}', 32)
        state.memory.store(0x400e0668, sr)
    
    proj.hook(address, put_symbol)

def copy_context(state, ql):
    for reg in ['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']:
        setattr(state.regs, reg, getattr(ql.reg, reg))

if __name__ == '__main__':
    entry, target = 0x805c5, 0x805d9
    path = "../examples/rootfs/mcu/sam3x8e/serial.ino.hex"
    
    ql = make_ql(path)

    history = []
    def read_cb(perip, offset, size, history):
        pass
    def write_cb(perip, offset, size, history):
        pass
    ql.hw.pmc.hook_read(read_cb, history)
    ql.hw.pmc.hook_write(write_cb, history)
    proj = make_angr(path)

    ql.run(end=entry)
    state = make_state(proj, entry)

    copy_context(state, ql)

    hook_read_register(proj, 0x805e2)
    hook_read_register(proj, 0x805ea)
    hook_read_register(proj, 0x805fe)
    hook_read_register(proj, 0x8060a)
    hook_read_register(proj, 0x80616)
    hook_read_register(proj, 0x80622)

    block = proj.factory.block(entry)
    block.pp
    
    target = 0x8062f
    # simgr = proj.factory.simgr(state)
    # simgr.explore(find=target)

    # for state in simgr.found:
    #     print(state)
    #     state.solver.simplify()
    #     for constraint in state.solver.constraints:
    #         print(f'\t{constraint}')

    while True:
        print(state)
        succ = state.step(num_inst=1)
        if len(succ.successors) > 1:
            break
        state = succ.successors[0]

# [=]     000805d2 [[FLASH]              + 0x0005d2]  1a 6a                         ldr                  r2, [r3, #0x20]
# [=]     [PMC] [0x805d2] [R] CKGR_MOR = 0x0
# [=]     000805d4 [[FLASH]              + 0x0005d4]  d2 01                         lsls                 r2, r2, #7
# [=]     000805d6 [[FLASH]              + 0x0005d6]  02 d5                         bpl                  #0x805de
# [=]     000805de [[FLASH]              + 0x0005de]  17 4a                         ldr                  r2, [pc, #0x5c]
# [=]     000805e0 [[FLASH]              + 0x0005e0]  1a 62                         str                  r2, [r3, #0x20]
# [=]     [PMC] [0x805e0] [W] CKGR_MOR = 0x370809 
# [=]     000805e2 [[FLASH]              + 0x0005e2]  9a 6e                         ldr                  r2, [r3, #0x68]
# [=]     [PMC] [0x805e2] [R] SR   = 0x1
# [=]     000805e4 [[FLASH]              + 0x0005e4]  d0 07                         lsls                 r0, r2, #0x1f
# [=]     000805e6 [[FLASH]              + 0x0005e6]  fc d5                         bpl                  #0x805e2
# [=]     000805e8 [[FLASH]              + 0x0005e8]  f6 e7                         b                    #0x805d8
# [=]     000805d8 [[FLASH]              + 0x0005d8]  17 4a                         ldr                  r2, [pc, #0x5c]
# [=]     000805da [[FLASH]              + 0x0005da]  1a 62                         str                  r2, [r3, #0x20]
# [=]     [PMC] [0x805da] [W] CKGR_MOR = 0x1370809
