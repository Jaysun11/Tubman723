import struct
import socket


# Define the Modbus Details
server_address = '192.168.1.???'
server_port = 502

# Create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to Modbus server
s.connect((server_address, server_port))

#This will run forever to monitor for problematic packets.
while True:
    # Get the data from a server and store it in the data variable
    data = s.recv(1024)
    #print the data
    print(data)

    # Check if data is a Modbus request
    if len(data) >= 12 and struct.unpack('>B', data[7:8])[0] == 3:
        # Parse Modbus request
        slave_id = struct.unpack('>B', data[6:7])[0]
        function_code = struct.unpack('>B', data[7:8])[0]
        start_address = struct.unpack('>H', data[8:10])[0]
        num_registers = struct.unpack('>H', data[10:12])[0]

        # Check for suspicious request parameters
        if (slave_id < 1 or slave_id > 247) or (function_code < 1 or function_code > 127) or (start_address < 0 or start_address > 65535) or (num_registers < 1 or num_registers > 125):
            print('Possible Modbus intrusion detected!')
            # Alert system administrator and take appropriate action
