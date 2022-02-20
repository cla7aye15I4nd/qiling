#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class Clint(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('msip'    , ctypes.c_uint32), # Offset: 0x0
            ('resvered', ctypes.c_uint32 * 0xfff),
            ('mtimecmp', ctypes.c_uint64), # Offset: 0x4000
            ('resvered', ctypes.c_uint64 * 0xffe),
            ('mtime'   , ctypes.c_uint64), # Offset: 0xBFF8
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.clint = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.clint) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.clint) + offset, data, size)