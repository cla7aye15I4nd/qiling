import sys, unittest
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407, stm32f411
from qiling.extensions.mcu.stm32f1 import stm32f103
from qiling.extensions.mcu.atmel   import sam3x8e
from qiling.extensions.mcu.gd32vf1 import gd32vf103

class SAM3X8Test(unittest.TestCase):
    def test_heat_press(self):
        """            
            Firmware    : Heat_Press
            MCU         : SAM3X8E
            Library     : Arduino
            Peripherals : ADC,PMC,UART,EFC0,EFC1,PIOA,PIOB,PIOC,PIOD,WDT,UOTGHS
            Comment     : 
                1. AFL is disabled in the test firmware.
                2. Maybe we need run it on the real board (TODO)
        """
        ql = Qiling(
            ["../examples/rootfs/mcu/sam3x8e/Heat_Press.ino.elf"],
            archtype="cortex_m", ostype="mcu", env=sam3x8e, 
        )

        ql.hw.create('wdt')
        ql.hw.create('efc0')
        ql.hw.create('efc1')
        ql.hw.create('pmc')
        ql.hw.create('pioa')
        ql.hw.create('piob')
        ql.hw.create('pioc')
        ql.hw.create('piod')
        ql.hw.create('adc')
        ql.hw.create('uart').watch()
        ql.hw.create('uotghs')

        ql.hw.systick.ratio = 100000
        ql.run(count=100000)
        self.assertTrue(len(ql.hw.uart.recv()) > 30)
        del ql

    def test_steering_control(self):
        """
            Firmware    : Steering_Control
            MCU         : SAM3X8E
            Library     : Arduino
            Peripherals : TC,ADC,PMC,UART,CHIPID,EFC1,PIOA,PIOB,PIOC,PIOD,WDT
            Comment     : 
                1. AFL is disabled in the test firmware.
                2. Enable `debug` and `voltageOut`.
                3. Identify the input. (TODO)
                4. Strange PIO logic in `countPulseASM` (Corner Case).
        """
        ql = Qiling(
            ["../examples/rootfs/mcu/sam3x8e/Steering_Control.ino.elf"],
            archtype="cortex_m", ostype="mcu", env=sam3x8e, 
        )

        ql.hw.create('tc1')
        ql.hw.create('wdt')
        ql.hw.create('efc0')
        ql.hw.create('efc1')
        ql.hw.create('pmc')
        ql.hw.create('pioa')
        ql.hw.create('piob')
        ql.hw.create('pioc')
        ql.hw.create('piod')
        ql.hw.create('adc')
        ql.hw.create('uart')
        ql.hw.create('uotghs')
        ql.hw.create('pdc_uart')

        ql.hw.systick.ratio = 100000
        ql.run(count=30000)

        print(ql.hw.uart.recv().decode())

        del ql

if __name__ == '__main__':
    unittest.main()
