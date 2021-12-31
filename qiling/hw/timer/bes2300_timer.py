#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class SingleTimer(ctypes.Structure):
    _fields_ = [
        ("Load"     , ctypes.c_uint32), # Offset: 0x000 (R/W)  Timer X Load
        ("Value"    , ctypes.c_uint32), # Offset: 0x004 (R/ )  Timer X Counter Current Value
        ("Control"  , ctypes.c_uint32), # Offset: 0x008 (R/W)  Timer X Control
        ("IntClr"   , ctypes.c_uint32), # Offset: 0x00C ( /W)  Timer X Interrupt Clear
        ("RIS"      , ctypes.c_uint32), # Offset: 0x010 (R/ )  Timer X Raw Interrupt Status
        ("MIS"      , ctypes.c_uint32), # Offset: 0x014 (R/ )  Timer X Masked Interrupt Status
        ("BGLoad"   , ctypes.c_uint32), # Offset: 0x018 (R/W)  Background Load Register
        ("RESERVED0", ctypes.c_uint32),
    ]

class ElapsedTimer(ctypes.Structure):
    _fields_ = [
        ("ElapsedCtrl", ctypes.c_uint32),
        ("ElapsedVal" , ctypes.c_uint32),
        ("RESERVED1"  , ctypes.c_uint32),
    ]

class BES2300Timer(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ("timer"        , SingleTimer * 2),
            ("elapsed_timer", ElapsedTimer * 2)
        ]
    
    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.timer = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.timer) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.timer) + offset, data, size)
