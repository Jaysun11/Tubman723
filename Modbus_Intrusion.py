from scapy.all import *
import struct
import datetime

#if set, the server_address will be used, if not the entire network will be sniffed
MANUAL = False

#dictionary used to store Modbus Packets
modbus_packets_processed = {}

# Define the Socket Details (if MANUAL boolean set)
server_address = '192.168.1.114'

# Get current time in iso format
def get_iso_time():
    local_timezone = datetime.datetime.now().replace(microsecond=0).isoformat()
    return local_timezone


def print_packet_details(slave_id, function_code, start_address, num_registers):
    #print packet details
    print("Processing Packet Details")
    print(slave_id)
    print(function_code)
    print(start_address)
    print(num_registers)

def parse_modbus_packet(payload):

    print('12 Byte payload recieved, verifying format...')

    # Parse Modbus TCP information
    transaction_id = struct.unpack('>H', payload[0:2])[0]
    protocol_id = struct.unpack('>H', payload[2:4])[0]
    length = struct.unpack('>H', payload[4:6])[0]
    unit_id = struct.unpack('>B', payload[6:7])[0]

    # Parse Modbus Data ADU
    function_code = struct.unpack('>B', payload[7:8])[0]
    start_address = struct.unpack('>H', payload[8:10])[0]
    num_registers = struct.unpack('>H', payload[10:12])[0]

    #store packet in a dictionary with current time
    packet_data =  {
        'timestamp': get_iso_time(),
        'transaction_id': transaction_id,
        'protocol_id': protocol_id,
        'length': length,
        'unit_id': unit_id,
        'function_code': function_code,
        'start_address': start_address,
        'number_of_registers': num_registers
    }

    print_packet_details(packet_data)
    check_modbus_validity(packet_data)

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

                # Check if data is a Modbus request by looking at attributes of payload
                if len(payload) == 12:

                    """
                        If the payload is 12 bytes long it is quite likely a modbus packet
                        Parse the packet to verify
                    """
                    parse_modbus_packet(payload)                

            except:
                #Packet was not a TCP Packet, cant be modbus so PASS
                pass



# Start sniffing the network traffic
if (not MANUAL):
    sniff(filter="tcp", prn=check_modbus)
else:
    sniff(filter="ip and host " + server_address + " tcp", prn=check_modbus)
