#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral


class BES2300Cache(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ("CACHE_ENABLE"      , ctypes.c_uint32), # 0x00
            ("CACHE_INI_CMD"     , ctypes.c_uint32), # 0x04
            ("WRITEBUFFER_ENABLE", ctypes.c_uint32), # 0x08
            ("WRITEBUFFER_FLUSH" , ctypes.c_uint32), # 0x0C
            ("LOCK_UNCACHEABLE"  , ctypes.c_uint32), # 0x10
            ("INVALIDATE_ADDRESS", ctypes.c_uint32), # 0x14
            ("INVALIDATE_SET_CMD", ctypes.c_uint32), # 0x18
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.cache = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.cache) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.cache) + offset, data, size)
