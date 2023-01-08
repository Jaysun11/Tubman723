#!/usr/bin/env python

from pymodbus.client.sync import ModbusSerialClient as ModbusClient
import logging

import time


logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.DEBUG)

client = ModbusClient(method='rtu', port='/dev/ttyUSB0', stopbits = 1, bytesize = 8, parity = 'N', baudrate= 9600)
client.connect()

while True:
    time.sleep(3)
    rr = client.read_input_registers(1, 21, unit=20)
    with open("modbus_sim.txt", "a") as f:  # open the file in append mode
        if (rr):
            #If there was a returned response (success)
            f.write(str(time.time()) + "\n")  # write the current timestamp to the file then a new line