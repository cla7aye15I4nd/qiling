import sys
import lief
import angr

sys.path.append('..')
from qiling.core import Qiling
from context import StateWrapper
from symbol import SymbolManager

class Skye:
    def __init__(self, path, env):
        self.env = env
        self.path = path
        
        self.emulator = self.create_emulator()
        self.emulator.hw.load_all()

        self.analyzer = self.create_analyzer()
        self.disassembler = self.emulator.disassembler

        self.symbol_manager = SymbolManager()

    def create_emulator(self):
        return Qiling(
            [self.path],
            env      = self.env, 
            ostype   = "mcu",
            archtype = "cortex_m",
        )

    def create_analyzer(self):
        return angr.Project(self.path, arch='ARMCortexM')

    def create_initial_state(self, address):
        return StateWrapper(self, self.analyzer.factory.blank_state(
            addr=address, 
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        ))

    def search(self, state, target, avoid):
        if state.addr in avoid:
            return

        self.history.append(state.addr)
        if state.addr == target:
            print('[END]')
            self.found.append(state)

        elif len(succs := state.step()) > 1:
            for succ in succs:
                if succ.addr not in self.history:
                    self.search(succ, target, avoid)

            for succ in succs:
                if succ.addr in self.history:
                    limit = 10
                    if len(self.history) > limit and \
                        succ.addr not in self.history[-limit:]:
                        self.search(succ, target, avoid)

        else:
            self.search(succs[0], target, avoid)

        self.history.pop(-1)

    def extract(self, begin, target, avoid=[]):
        self.emulator.run(end=begin)

        state = self.create_initial_state(begin)
        state.copy(self.emulator)

        self.found = []
        self.history = []
        self.search(state, target, avoid)

        for found in self.found:
            found.show_path()

if __name__ == '__main__':
    from qiling.extensions.mcu.atmel import sam3x8e
    from qiling.extensions.mcu.stm32f1 import stm32f103

    # skye = Skye('../examples/rootfs/mcu/sam3x8e/serial.ino.hex', sam3x8e)
    # skye.extract(0x805c5, 0x8062f)

    path = '/media/moe/keystone/MCUnitest/stm32f103rb-uart-test/build/stm32f103rb-uart-test'
    
    elf = lief.parse(path + '.elf')

    testcases = []
    avoid = []

    for outer in elf.exported_functions:
        if outer.name == 'Error_Handler':
            avoid.append(outer.address)        
        if outer.name.endswith('_test_begin'):
            print(outer)
            for inner in elf.exported_functions:
                if inner.name.endswith('_test_end'):                    
                    if inner.name[: -len('_test_end')] == outer.name[: -len('_test_begin')]:
                        print(outer, inner)
                        testcases.append((outer, inner))

    for test_begin, test_end in testcases:
        skye = Skye(path + '.hex', stm32f103)
        skye.extract(test_begin.address, test_end.address, avoid)
