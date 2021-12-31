#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class BES2300Aoncmu(QlPeripheral):
    class Type(ctypes.Structure):
        """ Clock Management Unit (CMU) provides general controls over the whole system """

        _fields_ = [
            ("CHIP_ID"        , ctypes.c_uint32),        #  0x00
            ("TOP_CLK_ENABLE" , ctypes.c_uint32),        #  0x04
            ("TOP_CLK_DISABLE", ctypes.c_uint32),        #  0x08
            ("RESET_PULSE"    , ctypes.c_uint32),        #  0x0C
            ("RESET_SET"      , ctypes.c_uint32),        #  0x10
            ("RESET_CLR"      , ctypes.c_uint32),        #  0x14
            ("CLK_SELECT"     , ctypes.c_uint32),        #  0x18
            ("CLK_OUT"        , ctypes.c_uint32),        #  0x1C
            ("WRITE_UNLOCK"   , ctypes.c_uint32),        #  0x20
            ("MEMSC"          , ctypes.c_uint32 * 4),    #  0x24
            ("MEMSC_STATUS"   , ctypes.c_uint32),        #  0x34
            ("BOOTMODE"       , ctypes.c_uint32),        #  0x38
            ("RESERVED_03C"   , ctypes.c_uint32),        #  0x3C
            ("MOD_CLK_ENABLE" , ctypes.c_uint32),        #  0x40
            ("MOD_CLK_DISABLE", ctypes.c_uint32),        #  0x44
            ("MOD_CLK_MODE"   , ctypes.c_uint32),        #  0x48
            ("CODEC_DIV"      , ctypes.c_uint32),        #  0x4C
            ("TIMER_CLK"      , ctypes.c_uint32),        #  0x50
            ("PWM01_CLK"      , ctypes.c_uint32),        #  0x54
            ("PWM23_CLK"      , ctypes.c_uint32),        #  0x58
            ("RAM_CFG"        , ctypes.c_uint32),        #  0x5C
            ("RESERVED_060"   , ctypes.c_uint32),        #  0x60
            ("PCM_I2S_CLK"    , ctypes.c_uint32),        #  0x64
            ("SPDIF_CLK"      , ctypes.c_uint32),        #  0x68
            ("SLEEP_TIMER_OSC", ctypes.c_uint32),        #  0x6C
            ("SLEEP_TIMER_32K", ctypes.c_uint32),        #  0x70
            ("STORE_GPIO_MASK", ctypes.c_uint32),        #  0x74
            ("CODEC_IIR"      , ctypes.c_uint32),        #  0x78
            ("RESERVED_07C"   , ctypes.c_uint32 * 0x1D), #  0x7C
            ("WAKEUP_PC"      , ctypes.c_uint32),        #  0xF0
            ("DEBUG_RES"      , ctypes.c_uint32 * 2),    #  0xF4
            ("CHIP_FEATURE"   , ctypes.c_uint32),        #  0xFC
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.aoncmu = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.aoncmu) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.aoncmu) + offset, data, size)
