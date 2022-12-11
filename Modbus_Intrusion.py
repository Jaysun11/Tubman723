from scapy.all import *
import struct
import datetime
import time

#if set, the server_address will be used, if not the entire network will be sniffed
MANUAL = True

#The time factor (seconds), is the allowable difference in time disparity
"""

    For example.. If packet 1 came in at 10:00:00, and packet 2 came in at 10:00:30,
    and packet 3 came in at 10:00:37, the time disparity would be... 23 seconds.

    Formula below

    T1 = 10:00:00

    T2 = 10:00:30

    T3 = 10:00:37

    Tprev = T2 - T1 = 30 seconds

    Tcurr =  T3 - Tprev = 7 seconds

    Tdisp = Tprev - Tcurr

    Tdisp = |30 - 7| = 23 Seconds.

"""

TIME_FACTOR = 2

# Set the threshold for the number of connections within a certain time period
#This is used to identify a DOS attack
CONNECTION_THRESHOLD = 60
TIME_PERIOD = 60  # seconds


#list used to store Modbus Packets
modbus_packets_processed = []

# Define the Socket Details (if MANUAL boolean set)
server_address = '127.0.0.1'

# Get current time in iso format
def get_iso_time():
    local_timezone = datetime.datetime.now().replace(microsecond=0).isoformat()
    return local_timezone


def print_packet_details(packet_data):
    #print packet details
    print("Processing Packet Details")
    print(packet_data)

def parse_modbus_packet(payload, source_IP_ADDRESS):

    print('12 Byte payload recieved, verifying format...')

    # Parse Modbus TCP information
    transaction_id = struct.unpack('>H', payload[0:2])[0]
    protocol_id = struct.unpack('>H', payload[2:4])[0]
    length = struct.unpack('>H', payload[4:6])[0]
    unit_id = struct.unpack('>B', payload[6:7])[0]

    # Parse Modbus Data ADU
    function_code = struct.unpack('>B', payload[7:8])[0]
    start_address = struct.unpack('>H', payload[8:10])[0]
    number_of_registers = struct.unpack('>H', payload[10:12])[0]

    #store packet in a dictionary with current time
    packet_data =  {
        'timestamp': get_iso_time(),
        'origin_ip': source_IP_ADDRESS,
        'transaction_id': transaction_id,
        'protocol_id': protocol_id,
        'length': length,
        'unit_id': unit_id,
        'function_code': function_code,
        'start_address': start_address,
        'number_of_registers': number_of_registers,
        'alert': False
    }

    print_packet_details(packet_data)
    check_modbus_validity(packet_data)

def check_modbus_validity(packet_data):     
    
    # Check for suspicious request parameters
    if (packet_data['unit_id'] < 1 or packet_data['unit_id'] > 247) or (packet_data['function_code'] < 1 or packet_data['function_code']  > 127) or (packet_data['start_address']  < 0 or packet_data['start_address'] > 65535) or (packet_data['start_address'] < 1 or packet_data['number_of_registers'] > 125):
        print('Possible Modbus intrusion detected! (False packet)')
        packet_data['alert'] = True
        # Alert system administrator and take appropriate action

    #calculate time disparity, if too short, could be a MITM attack
    check_time_disparity()
    
    check_if_first_time_origin(packet_data)
    
def check_if_first_time_origin(packet_data):
    global ip_counter
    if(ip_counter[packet_data['origin_ip']] == 1):
        print('Possible Modbus intrusion detected! (First time recieved from origin)')
        packet_data['alert'] = True

def check_time_disparity():
    if (len(modbus_packets_processed) >=3):
        last_3_packets = modbus_packets_processed[-3:]
        T1 = last_3_packets[0]['timestamp'].total_seconds()
        T2 = last_3_packets[1]['timestamp'].total_seconds()
        T3 = last_3_packets[2]['timestamp'].total_seconds()
        Tprev = T2 - T1
        Tcurr = T3 - T2
        Tdisp = abs(Tprev - Tcurr)
        
        if (Tdisp > TIME_FACTOR):
            last_3_packets[2]['alert'] = True
            print('Possible Modbus intrusion detected (MITM)!')

        

    



# Create a packet callback function
def check_modbus(packet):
    global start_time
    global ip_counter

    #check IP
    source_IP_ADDRESS = packet[IP].src

    #Record that IP

    if source_IP_ADDRESS in ip_counter:
        # Exists - Add 1 to the IP Count
        ip_counter[source_IP_ADDRESS] += 1
    else:
        # Doesn't exist - Set the value to 1 as this is the first occurence.
        ip_counter[source_IP_ADDRESS] = 1

    #reset values after time threshold    
    if (start_time - time.time() > TIME_PERIOD):
        start_time = time.time()
        ip_counter = {}

    else:
        if (ip_counter[source_IP_ADDRESS] >= CONNECTION_THRESHOLD):
            #If there has CONNECTION_THRESHOLD to many connections in the last TIME_THRESHOLD seconds.
            print("Warning! Possible DOS attack")

    
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
                    parse_modbus_packet(payload, source_IP_ADDRESS)                

            except:
                #Packet was not a TCP Packet, cant be modbus so PASS
                pass



def main():
    # Start sniffing the network traffic
    if (not MANUAL):
        sniff(filter="tcp", prn=check_modbus)
    else:
        sniff(filter="ip and host " + server_address, prn=check_modbus)

if __name__ == "__main__":
    global start_time
    global ip_counter
    ip_counter = {}
    start_time = time.time()
    main()