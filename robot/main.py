import os
import sys
import lief

sys.path.append('..')

# Qiling setting
from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407


## environment setting
firmware = "firmware/sdio-demo.elf"
log_file = 'run.log'


## Clear Log File
os.path.exists(log_file) and os.remove(log_file)


## Create Qiling Entity
ql = Qiling([firmware], archtype="cortex_m", env=stm32f407, verbose=QL_VERBOSE.DEFAULT, log_file=log_file)

ql.hw.create('flash interface')
ql.hw.create('rcc')
ql.hw.create('pwr')
ql.hw.create('gpioa')
ql.hw.create('gpioc')
ql.hw.create('gpiod')
ql.hw.create('usart1')
ql.hw.create('sdio').watch()


## Create lief Entity
binary = lief.parse(firmware)


## Function trace
trace = []


def nice(name):
    return 'SD' in name

def create_function_callback(ql):
    def function_cb(ql, address, size, trace):
        if ql.arch.is_handler_mode():
            return
        
        def logger(name):
            return (ql.log.info) if nice(name) else (ql.log.debug)

        count = 0
        for function in trace[::-1]:
            lo = function.address & 0xfffffffe
            up = lo + function.size

            if lo <= address < up:
                for _ in range(count):
                    function = trace.pop(-1)
                    logger(function.name)(f'Exit {function.name} = {hex(ql.reg.r0)}')
                
                break

            count += 1

        for function in binary.functions:
            entry_address = function.address & 0xfffffffe

            if entry_address == address:
                trace.append(function)
                logger(function.name)(f'Enter {function.name}[{hex(entry_address)}]')

                if nice(function.name):
                    setup_angr()

                break

    ql.hook_code(function_cb, user_data=trace)

def print_trace():
    ql.log.info('======= Function Trace ======')
    for func in trace:
        ql.log.info(func)


# Angr setting

def setup_angr():
    pass


if __name__ == '__main__':
    create_function_callback(ql)

    ql.hw.systick.ratio = 0x100
    ql.run(count=25000)

    print_trace()