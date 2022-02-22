import sys
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

    def search(self, state, end):
        self.history.append(state.addr)
        if state.addr == end:
            print('[END]')
            self.found.append(state)

        elif len(succs := state.step()) > 1:
            for succ in succs:
                if succ.addr not in self.history:
                    self.search(succ, end)

        else:
            self.search(succs[0], end)

        self.history.pop(-1)

    def extract(self, begin, end):
        self.emulator.run(end=begin)

        state = self.create_initial_state(begin)
        state.copy(self.emulator)

        self.found = []
        self.history = []
        self.search(state, end)

        for found in self.found:
            found.show_path()

if __name__ == '__main__':
    from qiling.extensions.mcu.atmel import sam3x8e

    skye = Skye('../examples/rootfs/mcu/sam3x8e/serial.ino.hex', sam3x8e)
    skye.extract(0x805c5, 0x8062f)
