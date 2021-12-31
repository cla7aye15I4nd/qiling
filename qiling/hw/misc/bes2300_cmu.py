#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class BES2300Cmu(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ("HCLK_ENABLE"    , ctypes.c_uint32),     #  0x00
            ("HCLK_DISABLE"   , ctypes.c_uint32),     #  0x04
            ("PCLK_ENABLE"    , ctypes.c_uint32),     #  0x08
            ("PCLK_DISABLE"   , ctypes.c_uint32),     #  0x0C
            ("OCLK_ENABLE"    , ctypes.c_uint32),     #  0x10
            ("OCLK_DISABLE"   , ctypes.c_uint32),     #  0x14
            ("HCLK_MODE"      , ctypes.c_uint32),     #  0x18
            ("PCLK_MODE"      , ctypes.c_uint32),     #  0x1C
            ("OCLK_MODE"      , ctypes.c_uint32),     #  0x20
            ("RESERVED_024"   , ctypes.c_uint32),     #  0x24
            ("HRESET_PULSE"   , ctypes.c_uint32),     #  0x28
            ("PRESET_PULSE"   , ctypes.c_uint32),     #  0x2C
            ("ORESET_PULSE"   , ctypes.c_uint32),     #  0x30
            ("HRESET_SET"     , ctypes.c_uint32),     #  0x34
            ("HRESET_CLR"     , ctypes.c_uint32),     #  0x38
            ("PRESET_SET"     , ctypes.c_uint32),     #  0x3C
            ("PRESET_CLR"     , ctypes.c_uint32),     #  0x40
            ("ORESET_SET"     , ctypes.c_uint32),     #  0x44
            ("ORESET_CLR"     , ctypes.c_uint32),     #  0x48
            ("TIMER0_CLK"     , ctypes.c_uint32),     #  0x4C
            ("BOOTMODE"       , ctypes.c_uint32),     #  0x50
            ("MCU_TIMER"      , ctypes.c_uint32),     #  0x54
            ("SLEEP"          , ctypes.c_uint32),     #  0x58
            ("PERIPH_CLK"     , ctypes.c_uint32),     #  0x5C
            ("SYS_CLK_ENABLE" , ctypes.c_uint32),     #  0x60
            ("SYS_CLK_DISABLE", ctypes.c_uint32),     #  0x64
            ("RESERVED_068"   , ctypes.c_uint32),     #  0x68
            ("BOOT_DVS"       , ctypes.c_uint32),     #  0x6C
            ("UART_CLK"       , ctypes.c_uint32),     #  0x70
            ("I2C_CLK"        , ctypes.c_uint32),     #  0x74
            ("RAM_CFG0"       , ctypes.c_uint32),     #  0x78
            ("RAM_CFG1"       , ctypes.c_uint32),     #  0x7C
            ("WRITE_UNLOCK"   , ctypes.c_uint32),     #  0x80
            ("WAKEUP_MASK0"   , ctypes.c_uint32),     #  0x84
            ("WAKEUP_MASK1"   , ctypes.c_uint32),     #  0x88
            ("WAKEUP_CLK_CFG" , ctypes.c_uint32),     #  0x8C
            ("TIMER1_CLK"     , ctypes.c_uint32),     #  0x90
            ("TIMER2_CLK"     , ctypes.c_uint32),     #  0x94
            ("RESERVED_098"   , ctypes.c_uint32),     #  0x98
            ("RESERVED_09C"   , ctypes.c_uint32),     #  0x9C
            ("ISIRQ_SET"      , ctypes.c_uint32),     #  0xA0
            ("ISIRQ_CLR"      , ctypes.c_uint32),     #  0xA4
            ("SYS_DIV"        , ctypes.c_uint32),     #  0xA8
            ("DMA_CFG"        , ctypes.c_uint32),     #  0xAC
            ("MCU2BT_INTMASK0", ctypes.c_uint32),     #  0xB0
            ("MCU2BT_INTMASK1", ctypes.c_uint32),     #  0xB4
            ("RESERVED_0B8"   , ctypes.c_uint32),     #  0xB8
            ("RESERVED_0BC"   , ctypes.c_uint32),     #  0xBC
            ("MEMSC"          , ctypes.c_uint32 * 4), #  0xC0
            ("MEMSC_STATUS"   , ctypes.c_uint32),     #  0xD0
            ("RESERVED2"      , ctypes.c_uint32 * 7), #  0xD4
            ("MISC"           , ctypes.c_uint32),     #  0xF0
            ("SIMU_RES"       , ctypes.c_uint32),     #  0xF4
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.cmu = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.cmu) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.cmu) + offset, data, size)
