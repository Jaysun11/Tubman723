from scapy.all import *
import struct

# Define the Socket Details (if MANUAL boolean set)
server_address = '192.168.1.114'

MANUAL = False

def print_packet_details(slave_id, function_code, start_address, num_registers):
    #print packet details
    print("Modbus Packet Details")
    print(slave_id)
    print(function_code)
    print(start_address)
    print(num_registers)

def parse_modbus_packet(payload):

    slave_id = struct.unpack('>B', payload[6:7])[0]
    function_code = struct.unpack('>B', payload[7:8])[0]
    start_address = struct.unpack('>H', payload[8:10])[0]
    num_registers = struct.unpack('>H', payload[10:12])[0]

    print_packet_details(slave_id, function_code, start_address, num_registers)
    check_modbus_validity(slave_id, function_code, start_address, num_registers)

def check_modbus_validity(slave_id, function_code, start_address, num_registers):     
    
    # Check for suspicious request parameters
    if (slave_id < 1 or slave_id > 247) or (function_code < 1 or function_code > 127) or (start_address < 0 or start_address > 65535) or (num_registers < 1 or num_registers > 125):
        print('Possible Modbus intrusion detected!')
        # Alert system administrator and take appropriate action




# Create a packet callback function
def check_modbus(packet):
    
    # If the packet has a TCP layer, check if it is a Modbus TCP packet
    if packet.haslayer(TCP):
        # Extract the TCP payload
        payload = packet[TCP].payload

        # If the payload is not None, try to read the Modbus packet
        if payload is not None:
            try:

                print('Payload Recieved, has TCP header, checking if it was a Modbus request')
        
                # Check if data is a Modbus request by looking at attributes of payload
                if len(payload) >= 12 and struct.unpack('>B', payload[7:8])[0] == 3:
                    print("here")
                    parse_modbus_packet(payload)                
                    
            except:
                #Packet was not a TCP Packet, cant be modbus so PASS
                pass



# Start sniffing the network traffic
if (not MANUAL):
    sniff(prn=check_modbus)
else:
    sniff(filter="ip and host " + server_address, prn=check_modbus)