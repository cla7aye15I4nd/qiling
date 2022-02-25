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

            if self.limit > 0 and len(self.history) > self.limit:
                for succ in succs:
                    if succ.addr in self.history and succ.addr not in self.history[-self.limit:]:
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

        self.limit = 0
        self.search(state, target, avoid)

        self.limit = 50
        while not self.found and self.limit > 0:
            self.search(state, target, avoid)
            self.limit -= 10

        return self.found
