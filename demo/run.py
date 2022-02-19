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

def hook_address(proj, address):
    def put_symbol(state):
        sr = claripy.BVS(f'SR#{hex(address)[2:]}', 32)
        state.memory.store(0x400e0668, sr)
    
    proj.hook(address, put_symbol)

if __name__ == '__main__':
    entry, target = 0x805c5, 0x805d9
    path = "../examples/rootfs/mcu/sam3x8e/serial.ino.hex"
    
    ql = make_ql(path)
    ql.run(end=entry)
    
    proj = make_angr(path)
    state = make_state(proj, entry)

    hook_address(proj, 0x805e2)
    hook_address(proj, 0x805ea)
    hook_address(proj, 0x805fe)
    hook_address(proj, 0x8060a)
    hook_address(proj, 0x80616)
    hook_address(proj, 0x80622)
    
    target = 0x8062f
    simgr = proj.factory.simgr(state)
    simgr.explore(find=target)

    if simgr.found:
        state = simgr.found[0]
        state.solver.simplify()
        for constraint in state.solver.constraints:
            print(f'\t{constraint}')

    # while True:
    #     succ = state.step()
    #     if len(succ.successors) > 1:
    #         break
    #     state = succ.successors[0]
    
    # for state in succ.successors:
    #     print(f'{state}:')
    #     state.solver.simplify()
    #     for constraint in state.solver.constraints:
    #         print(f'\t{constraint}')

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
