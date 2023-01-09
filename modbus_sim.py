#!/usr/bin/env python

from pymodbus.client.sync import ModbusTcpClient as ModbusClient

from datetime import datetime
import time

client = ModbusClient('192.168.1.230')
client.connect()


while True:
    time.sleep(3)
    rr = client.read_input_registers(0, 10, unit=1)
    with open("modbus_sim.txt", "a") as f:  # open the file in append mode
        if (rr):
            #If there was a returned response (success)
            # Get the current date and time
            now = datetime.now()

            # Use the strftime function to format the date and time
            date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

            f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line