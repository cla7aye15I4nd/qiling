import os
import sys
import lief

# import angr
# import claripy

sys.path.append('..')
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

def need_monitor(name):
    return 'SD' in name

def create_entry_callback(ql, function, trace):
    entry_address = function.address & 0xfffffffe

    def entry_cb(ql, trace):
        if ql.arch.is_handler_mode():
            return

        def logger(name):
            return (ql.log.info) if need_monitor(name) else (ql.log.debug)

        trace.append(function)
        logger(function.name)(f'Enter {function.name}[{hex(entry_address)}]')

    ql.hook_address(entry_cb, entry_address, user_data=trace)
    ql.log.debug(f'Hook Entry: ({hex(entry_address)}) {function}')

def create_exit_callback(ql, trace):
    def exit_cb(ql, address, size, trace):
        if ql.arch.is_handler_mode():
            return
        
        def logger(name):
            return (ql.log.info) if need_monitor(name) else (ql.log.debug)

        pop, count = 0, 0
        for function in trace[::-1]:
            lo = function.address & 0xfffffffe
            up = lo + function.size

            if lo <= address < up:
                pop = 1
                break

            count += 1

        while pop and count > 0:
            count -= 1
            function = trace.pop(-1)
            logger(function.name)(f'Exit {function.name} = {hex(ql.reg.r0)}')

    ql.hook_code(exit_cb, user_data=trace)

def print_trace():
    ql.log.info('======= Function Trace ======')
    for func in trace:
        ql.log.info(func)

create_exit_callback(ql, trace)
for function in binary.functions:
    create_entry_callback(ql, function, trace)

ql.hw.systick.ratio = 0x100
ql.run(count=25000)

print_trace()