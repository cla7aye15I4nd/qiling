#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral


class VirtIO(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('MagicValue'      , ctypes.c_uint32), # Offset: 0x0
            ('Version'         , ctypes.c_uint32), # Offset: 0x4
            ('DeviceId'        , ctypes.c_uint32), # Offset: 0x8
            ('VendorId'        , ctypes.c_uint32), # Offset: 0xc
            ('HostFeatures'    , ctypes.c_uint32), # Offset: 0x10
            ('HostFeaturesSel' , ctypes.c_uint32), # Offset: 0x14
            ('Resvered0'       , ctypes.c_uint32 * 2),
            ('GuestFeatures'   , ctypes.c_uint32), # Offset: 0x20
            ('GuestFeaturesSel', ctypes.c_uint32), # Offset: 0x24
            ('GuestPageSize'   , ctypes.c_uint32), # Offset: 0x28
            ('Resvered1'       , ctypes.c_uint32),
            ('QueueSel'        , ctypes.c_uint32), # Offset: 0x30
            ('QueueNumMax'     , ctypes.c_uint32), # Offset: 0x34
            ('QueueNum'        , ctypes.c_uint32), # Offset: 0x38
            ('QueueAlign'      , ctypes.c_uint32), # Offset: 0x3c
            ('QueuePfn'        , ctypes.c_uint32), # Offset: 0x40
            ('Resvered2'       , ctypes.c_uint32 * 3),
            ('QueueNotify'     , ctypes.c_uint32), # Offset: 0x50
            ('Resvered3'       , ctypes.c_uint32 * 3),
            ('InterruptStatus' , ctypes.c_uint32), # Offset: 0x60
            ('InterruptAck'    , ctypes.c_uint32), # Offset: 0x64
            ('Resvered4'       , ctypes.c_uint32 * 2),
            ('Status'          , ctypes.c_uint32), # Offset: 0x70
            ('Resvered5'       , ctypes.c_uint32 * 35),
            ('Config'          , ctypes.c_uint32), # Offset: 0x100
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.virtio = self.struct(
            MagicValue = 0x74726976,
            Version = 1,
            DeviceId = 2,
            VendorId = 0x554d4551,
            QueueNumMax = 8,
        )

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.virtio) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.virtio) + offset, data, size)
