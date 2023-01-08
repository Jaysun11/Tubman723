#!/usr/bin/env python

from pymodbus.client.sync import ModbusSerialClient as ModbusClient
import logging

import time
import random


logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.DEBUG)

def send_command():
    client = ModbusClient(method='rtu', port='/dev/ttyUSB0', timeout=20,stopbits = 1, bytesize = 8, parity = 'N', baudrate= 9600)
    client.connect()
    client.read_input_registers(1, 21, unit=20)

    print("Time Stamp: " + time.time())
    with open("modbus_mitm.txt", "a") as f:  # open the file in append mode
        f.write(str(time.time()) + "\n")  # write the current timestamp to the file then a new line


while True:
    # Generate a random interval between 1 seconds and 30 seconds
    random_interval = random.uniform(1, 30)
    print(f"Interval generated... Waiting {random_interval:.2f} seconds before running mitm attack")
    time.sleep(random_interval)
    send_command()
