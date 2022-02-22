import sys
import angr

sys.path.append('..')
from qiling.core import Qiling
from context import StateWrapper


class Skye:
    def __init__(self, path, env):
        self.env = env
        self.path = path
        
        self.emulator = self.create_emulator()
        self.analyzer = self.create_analyzer()
        self.disassembler = self.emulator.disassembler

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
        if state.addr == end:
            return

        if len(succs := state.step()) > 1:
            return

        for succ in succs:
            self.search(succ, end)

    def extract(self, begin, end):
        self.emulator.run(end=begin)

        state = self.create_initial_state(begin)
        state.copy(self.emulator)

        for i in range(30):
            state = state.step()[0]

if __name__ == '__main__':
    from qiling.extensions.mcu.atmel import sam3x8e

    skye = Skye('../examples/rootfs/mcu/sam3x8e/serial.ino.hex', sam3x8e)
    skye.extract(0x805c5, 0x8062f)
