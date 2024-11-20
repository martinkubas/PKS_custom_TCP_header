import os
import socket
import threading
import struct
import headerStructure
import time
import crcmod
from headerStructure import header_flags

LOCAL_PORT = int(input("Enter your local port: "))
PEER_PORT = int(input("Enter the peer port: "))
LOCAL_IP = "127.0.0.1"
PEER_IP = "127.0.0.1"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LOCAL_IP, LOCAL_PORT))
WINDOW_SIZE = 15
WINDOW_BASE = 0
MAX_FRAGMENT_SIZE = 1024 - headerStructure.HEADER_SIZE
fragment_size = 1008

current_file_location = ""

unacknowledged_packets = {}
acknowledgment_timeout = 2  # seconds to wait before retransmitting a packet

is_terminated = False
connection_established = False

last_received_msg_time = time.time()
KEEPALIVE_INTERVAL = 5
KEEPALIVE_THRESHOLD = 15

local_seq_num, peer_seq_num, last_acknowledged_seq = 0, 0, 0  # Tracks the last acknowledged sequence number

def calculate_crc(data):
    crc16_func = crcmod.predefined.mkCrcFun('crc-16')
    return crc16_func(data)

def create_header(seq_num, ack_num, window, length, flags, checksum):
    offset = 0b00000000  # 8-bit offset
    return struct.pack(headerStructure.HEADER_FORMAT, seq_num, ack_num, window, length, flags, checksum, offset)

def create_packet(seq_num, ack_num, window, length, flags, data, bad_msg=False):
    checksum = 0
    header = create_header(seq_num, ack_num, window, length, flags, checksum)
    packet = header + data
    checksum = calculate_crc(packet)
    if bad_msg:
        checksum += 1
    checksum_header = create_header(seq_num, ack_num, window, length, flags, checksum)
    return checksum_header + data

def parse_header(packet):
    return struct.unpack(headerStructure.HEADER_FORMAT, packet[:headerStructure.HEADER_SIZE])

def establish_connection():
    global local_seq_num, connection_established
    if not connection_established:
        print("Initiating connection with SYN")
        local_seq_num += 1  # Increment for initial SYN
        packet = create_packet(local_seq_num, 0, 0, 0, header_flags.SYN, b'')
        sock.sendto(packet, (PEER_IP, PEER_PORT))
    else:
        print("Already connected")


def end_connection():
    global is_terminated, connection_established, local_seq_num, peer_seq_num
    if not connection_established:
        print("No active connection to end")
        return
    print("Ending connection with FIN")
    local_seq_num += 1
    packet = create_packet(local_seq_num, 0, 0, 0, header_flags.FIN, b'')
    sock.sendto(packet, (PEER_IP, PEER_PORT))
    connection_established = False


def send_messages(message, bad_msg=False):
    global local_seq_num
    if not connection_established:
        print("Connection not yet established, cannot send message")
        return
    if len(message) > fragment_size:

        fragments = [message[i:i + fragment_size] for i in range(0, len(message), fragment_size)]

        # Send each fragment with FRAG flag, except the last one
        i = 0
        while i < len(fragments):
            if (local_seq_num + 1) - WINDOW_BASE >= WINDOW_SIZE:
                time.sleep(0.1)  # Wait for space in the window
                continue

            fragment = fragments[i].encode()
            local_seq_num += 1
            flag = header_flags.FRAG if i < len(fragments) - 1 else header_flags.FRAGSTOP
            packet = create_packet(local_seq_num, peer_seq_num, 0, len(fragment), flag, fragment, bad_msg)
            sock.sendto(packet, (PEER_IP, PEER_PORT))

            unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, flag, fragment)
            print(f"Sent fragment {local_seq_num}, size: {len(fragment)} bytes")
            i += 1
    else:
        local_seq_num += 1
        data = message.encode()
        packet = create_packet(local_seq_num, peer_seq_num, 0, len(data), 0, data, bad_msg)
        unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, 0, data)
        print(f"Sending message '{message}' with seq_num {local_seq_num} and ack_num {peer_seq_num}")
        sock.sendto(packet, (PEER_IP, PEER_PORT))

def handle_unacknowledged_packets():
    while not is_terminated:
        current_time = time.time()
        for seq_num, (timestamp, seq_num, ack_num, flags, data) in list(unacknowledged_packets.items()):
            if current_time - timestamp > acknowledgment_timeout:
                print(f"Retransmitting packet with seq_num {seq_num}")
                packet = create_packet(seq_num, ack_num, 0, len(data), flags, data)
                sock.sendto(packet, (PEER_IP, PEER_PORT))
                unacknowledged_packets[seq_num] = (current_time, seq_num, ack_num, flags, data)
        time.sleep(0.5)

def send_file(file_path, bad_file=False):
    global local_seq_num

    if not connection_established:
        print("Connection not yet established, cannot send file")
        return

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    print(f"Sending file: {file_name} (size: {file_size} bytes)")

    # Send file start packet with metadata
    local_seq_num += 1
    start_packet = create_packet(local_seq_num, peer_seq_num, 0, len(file_name.encode()), header_flags.START, file_name.encode())
    sock.sendto(start_packet, (PEER_IP, PEER_PORT))
    unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, header_flags.START, file_name.encode())

    # Send file in fragments
    with open(file_path, 'rb') as file:
        data = file.read(fragment_size)
        while data:
            if (local_seq_num + 1) - WINDOW_BASE >= WINDOW_SIZE:
                time.sleep(0.1)  # Wait for space in the window
                continue
            local_seq_num += 1
            packet = create_packet(local_seq_num, peer_seq_num, 0, len(data), 0, data, bad_file)
            sock.sendto(packet, (PEER_IP, PEER_PORT))

            # Track each sent packet for acknowledgment handling
            unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, 0, data)
            print(f"Sent fragment {local_seq_num}, size: {len(data)} bytes")
            data = file.read(fragment_size)

    # Send STOP fragment to indicate end of transmission
    local_seq_num += 1
    stop_packet = create_packet(local_seq_num, peer_seq_num, 0, 0, header_flags.STOP, b'')
    sock.sendto(stop_packet, (PEER_IP, PEER_PORT))
    print("sent STOP fragment")
    unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, header_flags.STOP, b'')

def receive_file(start_seq_num, file_name="received_file.png"):
    global peer_seq_num, last_received_msg_time
    received_data = {}
    stop_seq_num = None  # To store the expected last sequence number
    received_stop = False

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            body = data[headerStructure.HEADER_SIZE:]
            seq_num, ack_num, window, length, flags, checksum, offset = parse_header(data)

            # Verify checksum
            checksum_calc_header = create_header(seq_num, ack_num, window, length, flags, 0)
            calculated_checksum = calculate_crc(checksum_calc_header + body)
            if calculated_checksum != checksum:
                print(f"Checksum mismatch for packet {seq_num}. Sending NACK.")
                nack_packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.NACK, b'')
                sock.sendto(nack_packet, addr)
                continue

            # Check if the packet is in the correct range for receiving
            if seq_num >= start_seq_num and (stop_seq_num is None or seq_num <= stop_seq_num):
                # Store received data using the sequence number
                received_data[seq_num] = body

                if seq_num >= peer_seq_num:  # Only update if seq_num is in sequence or higher
                    peer_seq_num = seq_num + 1  # Advance to expect the next packet

                print(f"Received fragment {seq_num}, size: {len(body)} bytes peer_seq_num: {peer_seq_num}")
                last_received_msg_time = time.time()

                # Send ACK for received packet
                ack_packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.ACK, b'')
                sock.sendto(ack_packet, addr)
                print(f"Sent ACK for seq_num {seq_num + 1}")

                # If STOP flag is detected, mark the last sequence number
                if flags == header_flags.STOP:
                    print("received stop")
                    received_stop = True
                    stop_seq_num = seq_num  # Expected last sequence number

            # Break only when STOP flag was received, and all sequence numbers in the range are received
            if received_stop:
                missing_fragments = set(range(start_seq_num + 1, stop_seq_num + 1)) - set(received_data.keys())
                if missing_fragments:
                    print(f"Waiting for missing fragments: {missing_fragments}")
                    time.sleep(0.1)
                    continue  # Continue to wait for missing packets

                # Once all fragments are received, process the file
                print("All fragments received. Processing file.")
                break
        except socket.timeout:
            continue
    print(f"curr_f_loc {current_file_location}, file_name {file_name}")
    full_path = os.path.join(current_file_location, file_name)
    with open(full_path, 'wb') as file:
        for i in sorted(received_data.keys()):
            file.write(received_data[i])


    print(f"File received successfully. Size: {os.path.getsize(file_name)} bytes Located: {full_path}")
    return



def receive_messages():
    global is_terminated, connection_established, last_received_msg_time, peer_seq_num, last_acknowledged_seq, local_seq_num,  WINDOW_BASE
    received_message = {}
    start_seq_num = None
    stop_seq_num = None  # To store the expected last sequence number
    received_stop = False
    while not is_terminated:
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(1024)
            body = data[headerStructure.HEADER_SIZE:]
            seq_num, ack_num, window, length, flags, checksum, offset = parse_header(data)


            checksum_calc_header = create_header(seq_num, ack_num, window, length, flags, 0)
            calculated_checksum = calculate_crc(checksum_calc_header + body)

            if calculated_checksum != checksum:
                print(f"Checksum mismatch! Packet may be corrupted. rec checksum: {checksum}, calc checksum: {calculated_checksum} Sending NACK.")
                nack_packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.NACK, b'')
                sock.sendto(nack_packet, addr)
                continue


            if flags == headerStructure.header_flags.SYN and not connection_established:
                print(f"\nReceived SYN from {addr}. Sending SYN-ACK...")
                peer_seq_num = seq_num + 1  # Advance to expect the next packet
                local_seq_num += 1  # Increment our own seq_num for SYN-ACK response
                packet = create_packet(local_seq_num, peer_seq_num, 0, 0, headerStructure.header_flags.SYN_ACK, b'')
                sock.sendto(packet, addr)


            elif flags == headerStructure.header_flags.SYN_ACK and not connection_established:
                print(f"\nReceived SYN-ACK from {addr}. Sending ACK to complete handshake...")
                peer_seq_num = seq_num + 1  # Advance to expect the next packet  # Update to expect the next peer sequence
                local_seq_num += 1  # Increment our own sequence for the final ACK
                packet = create_packet(local_seq_num, peer_seq_num, 0, 0, headerStructure.header_flags.ACK, b'')
                sock.sendto(packet, addr)
                connection_established = True
                last_received_msg_time = time.time()
                print("Connection established!")

            elif flags == headerStructure.header_flags.ACK and not connection_established:
                peer_seq_num = seq_num + 1  # Advance to expect the next packet # Update to expect the next peer sequence
                print("Received ACK for handshake. Connection established!")
                last_received_msg_time = time.time()
                connection_established = True

            elif flags == headerStructure.header_flags.ACK and connection_established:
                if seq_num >= peer_seq_num:  # Only update if seq_num is in sequence or higher
                    peer_seq_num = seq_num + 1  # Advance to expect the next packet

                print(f"Received ACK for sequence {ack_num}")
                last_acknowledged_seq = ack_num
                last_received_msg_time = time.time()

                # Remove acknowledged packets from unacknowledged_packets
                if ack_num - 1 in unacknowledged_packets:
                    del unacknowledged_packets[ack_num - 1]

                # Update WINDOW_BASE if the lowest unacknowledged packet is acknowledged
                # Find the smallest unacknowledged sequence number
                if unacknowledged_packets:
                    min_unacknowledged = min(unacknowledged_packets.keys())

                    WINDOW_BASE = min_unacknowledged
                    print(f"Updated WINDOW_BASE to {WINDOW_BASE}")
                else:
                    WINDOW_BASE = ack_num
            elif flags == headerStructure.header_flags.NACK:
                # Check if the NACK packet's ack_num corresponds to a packet in the unacknowledged_packets dictionary
                if ack_num - 1 in unacknowledged_packets:
                    print(f"Received NACK for packet with sequence number {ack_num - 1}, resending message.")

                    # Retrieve the packet details from unacknowledged_packets
                    ttimestamp, sseq_num, aack_num, fflags, ddata = unacknowledged_packets[ack_num - 1]

                    # Create a new packet with the same details
                    packet = create_packet(sseq_num, aack_num, 0, len(ddata), fflags, ddata)

                    # Send the packet
                    sock.sendto(packet, addr)

                    # Update the timestamp in unacknowledged_packets to avoid immediate retransmission
                    unacknowledged_packets[ack_num - 1] = (time.time(), seq_num, ack_num, flags, data)


            elif connection_established:
                if flags == header_flags.START:
                    ack_packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.ACK, b'')
                    sock.sendto(ack_packet, addr)
                    receive_file(seq_num, body.decode())
                    continue

                if flags == header_flags.KEEPALIVE:
                    print("Received keepalive, sending keepalive ack")
                    packet = create_packet(0, 0, 0, 0, header_flags.KEEPALIVE_ACK, b'')
                    sock.sendto(packet, addr)
                    last_received_msg_time = time.time()
                elif flags == header_flags.KEEPALIVE_ACK:
                    print("Received keepalive ack")
                    last_received_msg_time = time.time()


                elif flags == header_flags.FRAG:
                    if stop_seq_num is None or seq_num <= stop_seq_num:
                        received_message[seq_num] = body

                    if start_seq_num is None or seq_num < start_seq_num :
                        start_seq_num = seq_num

                    if seq_num >= peer_seq_num:  # Only update if seq_num is in sequence or higher
                        peer_seq_num = seq_num + 1  # Advance to expect the
                    print(f"Received msg fragment {seq_num}, size: {len(body)} bytes peer_seq_num: {peer_seq_num}")
                    last_received_msg_time = time.time()

                    ack_packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.ACK, b'')
                    sock.sendto(ack_packet, addr)
                    print(f"Sent ACK for seq_num {seq_num + 1}")
                    if received_stop and set(range(start_seq_num + 1, stop_seq_num + 1)) <= set(received_message.keys()):

                            # Process full message
                            print("Full message received:",''.join(received_message[seq].decode() for seq in sorted(received_message.keys())))

                            received_message = {}
                            start_seq_num, stop_seq_num, received_stop = None, None, False



                elif flags == header_flags.FRAGSTOP:
                    print("received stop")
                    received_stop = True
                    stop_seq_num = seq_num

                    received_message[seq_num] = body

                    ack_packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.ACK, b'')
                    sock.sendto(ack_packet, addr)
                    # Process full message
                    if received_stop and set(range(start_seq_num + 1, stop_seq_num + 1)) <= set(received_message.keys()):
                        print("Full fragmented message received:",''.join(received_message[seq].decode() for seq in sorted(received_message.keys())))

                        received_message = {}
                        start_seq_num, stop_seq_num, received_stop = None, None, False

                    # Check if the packet is in the correct sequence from peer
                elif seq_num <= peer_seq_num and seq_num != 0:
                    if seq_num == peer_seq_num:  # Only update if seq_num is in sequence or higher
                        peer_seq_num = seq_num + 1  # Advance to expect the next packet
                    print(f"Received packet with seq_num {seq_num}, peer_seq_num {peer_seq_num} ack_num {ack_num}, last_ack_seq {last_acknowledged_seq} flags {flags}, length {length}")

                    if length > 0:
                        message = body.decode()
                        print(f"\nMessage from {addr}: {message}")
                        last_received_msg_time = time.time()

                        # Send ACK for received packet
                        ack_packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.ACK, b'')
                        sock.sendto(ack_packet, addr)
                        print(f"Sent ACK for seq_num {seq_num + 1}")

            if flags == header_flags.FIN:
                print("Received FIN, sending ACK for FIN and closing connection.")
                connection_established = False
                packet = create_packet(local_seq_num, seq_num + 1, 0, 0, header_flags.FIN_ACK, b'')
                sock.sendto(packet, addr)

        except socket.timeout:
            continue
        except socket.error as e:
            print(f"Error receiving message: {e}")

def keepalive():
    global connection_established, local_seq_num
    while not is_terminated:
        if connection_established and time.time() - last_received_msg_time > KEEPALIVE_THRESHOLD:
            connection_established = False
            print("No message received for a while. Considering connection dead.")
            break
        elif connection_established and time.time() - last_received_msg_time > KEEPALIVE_INTERVAL:
            print("sending keepalive message")
            packet = create_packet(0, 0, 0, 0, header_flags.KEEPALIVE, b'')
            sock.sendto(packet, (PEER_IP, PEER_PORT))
        time.sleep(KEEPALIVE_INTERVAL)
def print_man():
    print("------------------------\n"
        "Ak chcete: \n"
        "nadviazat spojenie -> stlacte \"s\"\n"
        "ukoncit spojenie -> stlacte \"e\"\n"
        "uplne odist z programu -> stlacte \"ee\"\n\n"
          
        "poslat subor -> stlacte \"f + file_path (f C:\\file.png)\"\n"
        "poslat textovu spravu -> stlacte \"m + sprava (m ahoj)\"\n\n"
          
        "umyselne poslat zlu textovu spravu -> stlacte \"bm + sprava (bm ahoj)\"\n"
        "umyselne poslat zlu textovu spravu v subore(nefunkcne) -> stlacte \"bf + sprava (bf C:\\file.png)\"\n\n"
          
        "zmenit velkost fragmentu -> stlacte \"cfrs + cislo (cfrs 100)\"\n"
        "zmenit miesto ulozenia suborov -> stlacte \"cfl + miesto ulozenia (cfl + C:\\Users\\user\\Desktop)\"\n\n"
        
        "PRE ZNOVUVYPISANIE TEJTO SPRAVY STLACTE \"man\""
      "\n------------------------------")
def main():
    global is_terminated, fragment_size, current_file_location
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()
    keepalive_thread = threading.Thread(target=keepalive)
    keepalive_thread.start()
    unacknowledged_thread = threading.Thread(target=handle_unacknowledged_packets)
    unacknowledged_thread.start()

    print_man()

    while not is_terminated:
        choice = input()
        if choice == "man":
            print_man()
        elif choice[:4] == "cfrs": #change fragment size
            if 0 < int(choice[5:]) <= MAX_FRAGMENT_SIZE:
                fragment_size = int(choice[5:])
                print(f"fragment size: {fragment_size}")
            else:
                print(f"fragment size not within limits (1, {MAX_FRAGMENT_SIZE})")

        elif choice[:3] == "cfl":  # change file location
            new_location = choice[4:].strip()
            if os.path.isdir(new_location):
                current_file_location = new_location
                print(f"File location changed to {current_file_location}")
            else:
                print("Invalid directory. File location not changed.")

        elif choice[:2] == "bm":
            send_messages(choice[3:], bad_msg=True)
        elif choice[:2] == "bf":
            if not os.path.isfile(choice[3:]):
                print("File not found!")
                continue
            send_file(choice[3:], bad_file=True)

        elif choice[0] == 'm':
            send_messages(choice[2:])

        elif choice[0] == 'f':
            if not os.path.isfile(choice[2:]):
                print("File not found!")
                continue
            send_file(choice[2:])
        elif choice == "ee":
            is_terminated = True
            end_connection()
            receive_thread.join()
            break
        elif choice == "e":
            end_connection()
        elif choice == "s":
            establish_connection()


        else:
            print("nerozpoznany command, napiste \"man\" pre vypisanie manualu")

    keepalive_thread.join()
    unacknowledged_thread.join()

if __name__ == "__main__":
    main()