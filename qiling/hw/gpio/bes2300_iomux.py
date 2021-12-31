#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class BES2300Iomux(QlPeripheral):    
    class Type(ctypes.Structure):
        """ Pin multiplexing  """
        
        _fields_ = [
            ("REG_000", ctypes.c_uint32),
            ("REG_004", ctypes.c_uint32),
            ("REG_008", ctypes.c_uint32),
            ("REG_00C", ctypes.c_uint32),
            ("REG_010", ctypes.c_uint32),
            ("REG_014", ctypes.c_uint32),
            ("REG_018", ctypes.c_uint32),
            ("REG_01C", ctypes.c_uint32),
            ("REG_020", ctypes.c_uint32),
            ("REG_024", ctypes.c_uint32),
            ("REG_028", ctypes.c_uint32),
            ("REG_02C", ctypes.c_uint32),
            ("REG_030", ctypes.c_uint32),
            ("REG_034", ctypes.c_uint32),
            ("REG_038", ctypes.c_uint32),
            ("REG_03C", ctypes.c_uint32),
            ("REG_040", ctypes.c_uint32),
            ("REG_044", ctypes.c_uint32),
            ("REG_048", ctypes.c_uint32),
            ("REG_04C", ctypes.c_uint32),
            ("REG_050", ctypes.c_uint32),
            ("REG_054", ctypes.c_uint32),
            ("REG_058", ctypes.c_uint32),
            ("REG_05C", ctypes.c_uint32),
            ("REG_060", ctypes.c_uint32),
            ("REG_064", ctypes.c_uint32),
            ("REG_068", ctypes.c_uint32),
            ("REG_06C", ctypes.c_uint32),
            ("REG_070", ctypes.c_uint32),
            ("REG_074", ctypes.c_uint32),
            ("REG_078", ctypes.c_uint32),
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.iomux = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.iomux) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.iomux) + offset, data, size)
