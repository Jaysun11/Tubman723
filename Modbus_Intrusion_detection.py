from scapy.all import *
import struct
from datetime import datetime
import time


#if set, the server_address will be used, if not the entire network will be sniffed
MANUAL = False

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
CONNECTION_THRESHOLD = 150
TIME_PERIOD = 20 # seconds

# Define the Socket Details (if MANUAL boolean set)
server_address = '127.0.0.1'

# Get current time in iso format
def get_iso_time():
    local_timezone = datetime.now().replace(microsecond=0).isoformat()
    return local_timezone


def print_packet_details(packet_data):
    #print packet details
    print("Processing Packet Details")
    print(packet_data)

def parse_modbus_packet(payload, source_IP_ADDRESS):

    #print('12 Byte payload recieved, verifying format...')
    payload = bytes(payload)
    # Parse Modbus TCP information

    transaction_id = struct.unpack('>H', bytes(payload[0:2]))[0]
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

    check_modbus_validity(packet_data)
    

def check_modbus_validity(packet_data):     
    
    # Check for suspicious request parameters
    if (packet_data['unit_id'] < 1 or packet_data['unit_id'] > 247) or (packet_data['function_code'] < 1 or packet_data['function_code']  > 127) or (packet_data['start_address']  < 0 or packet_data['start_address'] > 65535) or (packet_data['number_of_registers'] < 1 or packet_data['number_of_registers'] > 125):
        print('Possible Modbus intrusion detected! (False packet)')
        print("Unit ID: " + str(packet_data['unit_id']))
        print("Function Code : " + str(packet_data['unit_id']))
        print("Start Address: " + str(packet_data['unit_id']))
        print("Number Of Registers : " + str(packet_data['number_of_registers']))
        
        print_packet_details(packet_data)

        
        with open("modbus_false_packet_detected.txt", "a") as f:  # open the file in append mode
            f.write("FALSE PACKET ATTACK DETECTED: \n")  # write the current timestamp to the file then a new line
            # Get the current date and time
            now = datetime.now()

            # Use the strftime function to format the date and time
            date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

            f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line
        packet_data['alert'] = True
        # Alert system administrator and take appropriate action
    else:
        #Valid Modbus packet, check for warnings

        #Record that IP
        record_IP(packet_data['origin_ip'])
        sys.stdout.flush()
        #calculate time disparity, if too short, could be a MITM attack
        record_packet(packet_data)
        sys.stdout.flush()
        check_time_disparity(packet_data)
        sys.stdout.flush()
        check_if_first_time_origin(packet_data)
        sys.stdout.flush()
    
def record_packet(packet_data):
    global modbus_packets_processed
    modbus_packets_processed.append(packet_data)

def check_if_first_time_origin(packet_data):
    global ip_counter

    if(ip_counter[packet_data['origin_ip']] == 1):
        
        print('Possible Modbus intrusion detected! (First time recieved from origin)')
        print_packet_details(packet_data)
        sys.stdout.flush()
        
        with open("modbus_mitm_detected.txt", "a") as f:  # open the file in append mode
            f.write("MITM (FIRST TIME) ATTACK DETECTED: \n")  # write the current timestamp to the file then a new line
            # Get the current date and time
            now = datetime.now()

            # Use the strftime function to format the date and time
            date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

            f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line
        packet_data['alert'] = True

def remove_up_to_character(string, character):
    # Find the index of the first occurrence of the character in the string
    index = string.find(character)

    # If the character is not found, return the original string
    if index == -1:
        return string

    # Return the string with all characters up to the first occurrence of the character removed
    return string[index + 1:]

def check_time_disparity(packet_data):
    global modbus_packets_processed

    if (len(modbus_packets_processed) >=3):
        last_3_packets = modbus_packets_processed[-3:]
        
        try:
            T1 = datetime.strptime(remove_up_to_character(last_3_packets[0]['timestamp'], "T"),'%H:%M:%S')
            T2 = datetime.strptime(remove_up_to_character(last_3_packets[1]['timestamp'], "T"),'%H:%M:%S')
            T3 = datetime.strptime(remove_up_to_character(last_3_packets[2]['timestamp'], "T"),'%H:%M:%S')
            Tprev = (T2 - T1).total_seconds()
            Tcurr = (T3 - T2).total_seconds()
            Tdisp = abs(Tprev - Tcurr)

            #
        
            if (Tdisp > TIME_FACTOR):
                last_3_packets[2]['alert'] = True
                print("TDiSP: ", Tdisp)
                print_packet_details(packet_data)
                print('Possible Modbus intrusion detected (MITM)!')
                sys.stdout.flush()
                with open("modbus_mitm_detected.txt", "a") as f:  # open the file in append mode
                    f.write("MITM ATTACK DETECTED: \n")  # write the current timestamp to the file then a new line
                    # Get the current date and time
                    now = datetime.now()

                    # Use the strftime function to format the date and time
                    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

                    f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line

        except Exception as e:
            print(e)
        

        

        

def record_IP(source_IP_ADDRESS):
    global ip_counter

    if source_IP_ADDRESS in ip_counter:
        # Exists - Add 1 to the IP Count
        ip_counter[source_IP_ADDRESS] += 1
    else:
        # Doesn't exist - Set the value to 1 as this is the first occurence.
        ip_counter[source_IP_ADDRESS] = 1

        
# Create a packet callback function
def check_modbus(packet):
    global start_time
    global ip_counter
    global dos_warning

    #check IP
    source_IP_ADDRESS = packet[IP].src

    #reset values after time threshold  

    if (time.time() - start_time > TIME_PERIOD):
        dos_warning = False
        start_time = time.time()
        ip_counter[source_IP_ADDRESS] = 1
        

    else:
        try:
            if (ip_counter[source_IP_ADDRESS] >= CONNECTION_THRESHOLD and dos_warning == False):
                #If there has CONNECTION_THRESHOLD to many connections in the last TIME_THRESHOLD seconds.
                print("Warning! Possible DOS attack")
                
                dos_warning = True
                with open("modbus_dos_detected.txt", "a") as f:  # open the file in append mode
                    f.write("DOS ATTACK DETECTED: \n")  # write the current timestamp to the file then a new line
                     # Get the current date and time
                    now = datetime.now()

                    # Use the strftime function to format the date and time
                    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

                    f.write(str(date_time) + "\n")  # write the current timestamp to the file then a new line
        except KeyError:
            #print("KEY ERROR on DOS Attack")
            pass

    
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
    global modbus_packets_processed
    global dos_warning
    dos_warning = False

    modbus_packets_processed = []
    ip_counter = {}
    start_time = time.time()
    main()