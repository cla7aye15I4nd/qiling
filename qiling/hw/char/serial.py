#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral


class Serial(QlConnectivityPeripheral):
	class Type(ctypes.Structure):
		_fields_ = [
			('THR', ctypes.c_uint8), # 0, RHR
			('IER', ctypes.c_uint8), # 1
			('FCR', ctypes.c_uint8), # 2, TSR
			('LCR', ctypes.c_uint8), # 3
			('MCR', ctypes.c_uint8), # 4
			('LSR', ctypes.c_uint8), # 5
			('MSR', ctypes.c_uint8), # 6
			('SPR', ctypes.c_uint8), # 7
		]

	def __init__(self, ql, label):
		super().__init__(ql, label)

		self.serial = self.struct(
			LSR = 1 << 5
		)

	@QlPeripheral.monitor()
	def read(self, offset: int, size: int) -> int:
		buf = ctypes.create_string_buffer(size)
		ctypes.memmove(buf, ctypes.addressof(self.serial) + offset, size)
		return int.from_bytes(buf.raw, byteorder='little')

	@QlPeripheral.monitor()
	def write(self, offset: int, size: int, value: int):      
		if offset == self.struct.THR.offset:
			self.send_to_user(value)

		data = (value).to_bytes(size, byteorder='little')
		ctypes.memmove(ctypes.addressof(self.serial) + offset, data, size)
