# qemu-system-riscv64 
#     -machine virt 
#     -bios none 
#     -kernel kernel/kernel 
#     -m 128M 
#     -smp 3 
#     -nographic 
#     -drive file=fs.img,if=none,format=raw,id=x0 
#     -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

import sys
sys.path.append('../..')

from qiling.core import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(
    ['../rootfs/kernel/xv6/kernel'], 
    ostype='kernel', verbose=QL_VERBOSE.DEFAULT, 
)

ql.mem.map(0x2000000 ,  0x10000)
ql.mem.map(0x0c000000, 0x240000)

ql.hw.setup_mmio(0x10001000, 0x1000, info="[VIRTIO]")
ql.hw.create('virtio0', 'VirtIO', 0x10001000)

ql.hw.setup_mmio(0x10000000, 0x1000, info="[UART0]")
ql.hw.create('uart0', 'Serial', 0x10000000)

ql.mem.map(0x4000000000-0x100000, 0x100000)

try:
    ql.run(count=10**8, end=0x80000070)
except:
    import ipdb; ipdb.set_trace()

print(hex(ql.reg.stvec))
print(hex(ql.reg.mtvec))