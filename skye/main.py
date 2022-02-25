import sys
import lief

sys.path.append('..')
from qiling.extensions.mcu.stm32f1 import stm32f103

from skye import Skye

path = '/media/moe/keystone/MCUnitest/stm32f103rb-uart-test/build/stm32f103rb-uart-test'

elf = lief.parse(path + '.elf')

testcases = []
avoid = []

for outer in elf.exported_functions:
    if outer.name == 'Error_Handler':
        avoid.append(outer.address)

    elif outer.name.endswith('_test_begin'):

        testname = outer.name[: -len('_test_begin')]
        for inner in elf.exported_functions:
            if inner.name.endswith('_test_end') and \
                    inner.name[: -len('_test_end')] == testname:                    
                testcases.append((testname, outer.address, inner.address))

for testname, test_begin, test_end in testcases:
    skye = Skye(path + '.hex', stm32f103)
    found = skye.extract(test_begin, test_end, avoid)

    with open(f'{testname}_path.log', 'w') as f:
        f.write(f'[{testname.upper()}]\n')
        for index, state in enumerate(found):
            f.write(f'\n[PATH {index + 1}]\n')
            for node in state.path:
                if type(node) is tuple:
                    ins, label, field, value = node
                    if ins.mnemonic.startswith('ldr'):
                        f.write(f'[{hex(ins.address)}] [R] {label}[{field}]\n')
                    else:
                        f.write(f'[{hex(ins.address)}] [W] {label}[{field}] = {value}\n')
                else:
                    f.write(f'{node}\n')

