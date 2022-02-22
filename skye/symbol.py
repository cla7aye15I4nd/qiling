import claripy

class SymbolManager:
    def __init__(self):
        self.symbol = {}

    def new_symbol(self, label, field, info={}):
        name = f'{label}[{field}]'
        sym = claripy.BVS(name, 32)

        self.symbol[name] = info
        self.symbol[name]['instance'] = sym

        return sym