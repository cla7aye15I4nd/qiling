#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral

class ContextInfo(ctypes.Structure):
    _fields_ = [
        ("PriorityThreshold", ctypes.c_uint32),
        ("ClaimOrComplete",   ctypes.c_uint32),
        ("Reserved",   ctypes.c_uint32 * 1022),
    ]

class Plic(QlPeripheral):
    """ 
        Platform-Level Interrupt Controller (PLIC)
        reference: https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic.adoc 
    """
    class Type(ctypes.Structure):
        _fields_ = [
            ("Priority"   , ctypes.c_uint32 * 1024),         # (Offset: 0x000000~0x000FFC) Interrupt source 0~1023 priority 
            ("Pending"    , ctypes.c_uint32 * 32),           # (Offset: 0x001000~0x00107C) Interrupt Pending bit 0~1023
            ("Reserved0"  , ctypes.c_uint32 * 992),
            ("Enable"     , (ctypes.c_uint32 * 32) * 15872), # (Offset: 0x002000~0x1F1FFC)
            ('Reserved'   , ctypes.c_uint32 * 14336),
            ("ContextInfo", ContextInfo * 15872)             # (Offset: 0x200000~0x4000000)
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.plic = self.struct()
