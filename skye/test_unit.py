import sys, unittest
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407, stm32f411
from qiling.extensions.mcu.stm32f1 import stm32f103
from qiling.extensions.mcu.atmel   import sam3x8e
from qiling.extensions.mcu.gd32vf1 import gd32vf103

class STM32F103RB(unittest.TestCase):
    def test_uart(self):
        ql = Qiling(
            ['/media/moe/keystone/MCUnitest/stm32f103rb-uart-test/build/stm32f103rb-uart-test.hex'],
            ostype="mcu", archtype="cortex_m", env=stm32f103
        )

        ql.hw.load_all()
        
        ql.hw.usart2.send(b'ABC')
        ql.run(count=10000)

        print(ql.hw.usart2.recv())

        del ql

    def test_spi(self):
        ql = Qiling(
            ['/media/moe/keystone/MCUnitest/stm32f103rb-spi-test/build/stm32f103rb-spi-test.hex'],
            ostype="mcu", archtype="cortex_m", env=stm32f103
        )

        ql.hw.load_all()
        ql.hw.spi1.watch()
        
        ql.hw.spi1.send(b'ABC')
        ql.run(count=10000)

        print(ql.hw.spi1.recv())

        del ql

    def test_adc(self):
        ql = Qiling(
            ['/media/moe/keystone/MCUnitest/stm32f103rb-adc-test/build/stm32f103rb-adc-test.hex'],
            ostype="mcu", archtype="cortex_m", env=stm32f103
        )

        ql.hw.load_all()
        ql.hw.adc1.watch()
        
        ql.run(count=10000)

        del ql

    def test_pwm(self):
        ql = Qiling(
            ['/media/moe/keystone/MCUnitest/stm32f103rb-pwm-test/build/stm32f103rb-pwm-test.hex'],
            ostype="mcu", archtype="cortex_m", env=stm32f103,
        )

        ql.hw.load_all()
        ql.hw.tim3.watch()

        ql.run(count=10000)

        del ql

if __name__ == '__main__':
    unittest.main()
