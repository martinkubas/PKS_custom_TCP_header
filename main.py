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

is_terminated = False
connection_established = False

LAST_RECEIVED_MSG_TIME = time.time()
KEEPALIVE_INTERVAL = 5
KEEPALIVE_THRESHOLD = 15

# Track sequence and acknowledgment numbers
local_seq_num = 0
peer_seq_num = 0
last_acknowledged_seq = 0  # Tracks the last acknowledged sequence number

fragment_size = 1
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
        # Send SYN with the current local sequence number
        local_seq_num += 1  # Increment for initial SYN
        packet = create_packet(local_seq_num, 0, 0, 0, header_flags.SYN, b'')
        sock.sendto(packet, (PEER_IP, PEER_PORT))
    else:
        print("Already connected")

def end_connection():
    global is_terminated, connection_established, local_seq_num, peer_seq_num
    if not connection_established:
        print("No active connection to end")

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

    local_seq_num += 1  # Increment local sequence number for each new message sent
    data = message.encode()
    packet = create_packet(local_seq_num, peer_seq_num, 0, len(data), 0, data, bad_msg)
    print(f"Sending message '{message}' with seq_num {local_seq_num} and ack_num {peer_seq_num}")
    sock.sendto(packet, (PEER_IP, PEER_PORT))

def send_file():
    global local_seq_num

    if not connection_established:
        print("Connection not yet established, cannot send file")
        return

    file_path = input("Enter path of the file to send: ")
    if not os.path.isfile(file_path):
        print("File not found!")
        return

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    print(f"Sending file: {file_name} (size: {file_size} bytes)")

    # Send file start packet with metadata
    local_seq_num += 1
    start_packet = create_packet(local_seq_num, peer_seq_num, 0,len(file_name.encode()), header_flags.START, file_name.encode())
    sock.sendto(start_packet, (PEER_IP, PEER_PORT))

    # Send file in fragments
    with open(file_path, 'rb') as file:
        while chunk := file.read(fragment_size):
            local_seq_num += 1
            packet = create_packet(local_seq_num, peer_seq_num, 0, len(chunk), 0, chunk)
            sock.sendto(packet, (PEER_IP, PEER_PORT))

            print(f"Sent fragment {local_seq_num}, size: {len(chunk)} bytes")


    # Send end-of-file packet
    local_seq_num += 1
    end_packet = create_packet(local_seq_num, peer_seq_num, 0, 0, header_flags.STOP, b'')
    sock.sendto(end_packet, (PEER_IP, PEER_PORT))
    print("File transfer complete.")


def receive_file(start_seq_num):
    global peer_seq_num
    received_data = {}
    file_start_time = time.time()
    file_name = "received_file.png"
    expected_seq_num = start_seq_num + 1

    while True:
        data, addr = sock.recvfrom(1024)
        body = data[headerStructure.HEADER_SIZE:]
        seq_num, ack_num, window, length, flags, checksum, offset = parse_header(data)

        # Calculate the checksum of the header and body
        checksum_calc_header = create_header(seq_num, ack_num, window, length, flags, 0)
        calculated_checksum = calculate_crc(checksum_calc_header + body)

        # Verify checksum
        if calculated_checksum != checksum:
            print(f"Checksum mismatch for packet {seq_num}. Requesting retransmission.")
            # Send NACK (negative acknowledgment) to request retransmission

            continue

        # Store the byte in the dictionary using the relative sequence number
        received_data[seq_num - (start_seq_num + 1)] = body
        expected_seq_num += 1  # Move to the next expected sequence number
        peer_seq_num = seq_num + 1
        print(f"Received byte fragment {seq_num}, size: {len(body)} bytes")

        # Detect the last packet in the sequence (if length < fragment_size)
        if length < fragment_size:
            break

    # Write received data to file in order
    with open(file_name, 'wb') as file:
        for i in sorted(received_data.keys()):
            file.write(received_data[i])

    print(f"File received successfully. Size: {os.path.getsize(file_name)} bytes, Duration: {time.time() - file_start_time} seconds")

def receive_messages():
    global is_terminated, connection_established, LAST_RECEIVED_MSG_TIME, peer_seq_num, last_acknowledged_seq, local_seq_num

    while not is_terminated:
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(1024)
            body = data[headerStructure.HEADER_SIZE:]
            seq_num, ack_num, window, length, flags, checksum, offset = parse_header(data)

            #print(f"Received packet with seq_num {seq_num}, ack_num {ack_num}, last_ack_seq {last_acknowledged_seq} flags {flags}, length {length}, data {body.decode()}")

            checksum_calc_header = create_header(seq_num, ack_num, window, length, flags, 0)
            calculated_checksum = calculate_crc(checksum_calc_header + body)
            if calculated_checksum != checksum:
                peer_seq_num += 1
                print(f"Checksum mismatch! Packet may be corrupted. rec checksum: {checksum}, calc checksum: {calculated_checksum}")
                continue


            if flags == headerStructure.header_flags.SYN and not connection_established:
                print(f"\nReceived SYN from {addr}. Sending SYN-ACK...")
                peer_seq_num = seq_num + 1  # Expect next packet with peer's seq_num + 1
                local_seq_num += 1  # Increment our own seq_num for SYN-ACK response
                packet = create_packet(local_seq_num, peer_seq_num, 0, 0, headerStructure.header_flags.SYN_ACK, b'')
                sock.sendto(packet, addr)


            elif flags == headerStructure.header_flags.SYN_ACK and not connection_established:
                print(f"\nReceived SYN-ACK from {addr}. Sending ACK to complete handshake...")
                peer_seq_num = seq_num + 1  # Update to expect the next peer sequence
                local_seq_num += 1  # Increment our own sequence for the final ACK
                packet = create_packet(local_seq_num, peer_seq_num, 0, 0, headerStructure.header_flags.ACK, b'')
                sock.sendto(packet, addr)
                connection_established = True
                LAST_RECEIVED_MSG_TIME = time.time()
                print("Connection established!")

            elif flags == headerStructure.header_flags.ACK and not connection_established:
                peer_seq_num = seq_num + 1  # Update to expect the next peer sequence
                print("Received ACK for handshake. Connection established!")
                LAST_RECEIVED_MSG_TIME = time.time()
                connection_established = True

            elif connection_established:
                if flags == header_flags.START:
                    receive_file(seq_num)
                elif flags == header_flags.KEEPALIVE:
                    print("Received keepalive, sending keepalive ack")
                    packet = create_packet(0, 0, 0, 0, header_flags.KEEPALIVE_ACK, b'')
                    sock.sendto(packet, addr)
                    LAST_RECEIVED_MSG_TIME = time.time()
                elif flags == header_flags.KEEPALIVE_ACK:
                    print("Received keepalive ack")
                    LAST_RECEIVED_MSG_TIME = time.time()

                print(f"Received packet with seq_num {seq_num}, peer_seq_num {peer_seq_num} ack_num {ack_num}, last_ack_seq {last_acknowledged_seq} flags {flags}, length {length}")
                if ack_num > last_acknowledged_seq and flags == header_flags.ACK:
                    print(f"Received ACK for sequence {ack_num}")
                    last_acknowledged_seq = ack_num
                    LAST_RECEIVED_MSG_TIME = time.time()

                # Check if the packet is in the correct sequence from peer
                if seq_num == peer_seq_num:
                    peer_seq_num += 1  # Increment expected peer sequence
                    if length > 0:
                        message = body.decode()
                        print(f"\nMessage from {addr}: {message}")
                        LAST_RECEIVED_MSG_TIME = time.time()

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
        if connection_established and time.time() - LAST_RECEIVED_MSG_TIME > KEEPALIVE_THRESHOLD:
            connection_established = False
            print("No message received for a while. Considering connection dead.")
            break
        elif connection_established and time.time() - LAST_RECEIVED_MSG_TIME > KEEPALIVE_INTERVAL:
            print("sending keepalive message")
            packet = create_packet(0, 0, 0, 0, header_flags.KEEPALIVE, b'')
            sock.sendto(packet, (PEER_IP, PEER_PORT))
        time.sleep(KEEPALIVE_INTERVAL)

def main():
    global is_terminated
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()
    keepalive_thread = threading.Thread(target=keepalive)
    keepalive_thread.start()

    print("------------------------\n"
          "Ak chcete: \n"
          "poslat subor(nefunkcne) -> stlacte \"f\"\n"
          "ukoncit spojenie -> stlacte \"e\"\n"
          "nadviazat spojenie -> stlacte \"s\"\n"
          "umyselne poslat zlu spravu(nefunkcne) -> stlacte \"b+sprava (b ahoj)\"\n"
          "uplne odist z programu -> stlacte \"ee\"\n"
          "!!!AKEKOLVEK INE ZNAKY SA POSLU AKO SPRAVA DRUHEMU POCITACU!!!"
          "\n------------------------------")

    while not is_terminated:
        choice = input()
        if choice == "f":
            send_file()
        elif choice == "e":
            end_connection()
        elif choice == "s":
            establish_connection()
        elif choice[0] == 'b':
            send_messages(choice[2:], bad_msg=True)
        elif choice == "ee":
            is_terminated = True
            end_connection()
            receive_thread.join()

            break
        else:
            send_messages(choice)

    keepalive_thread.join()

if __name__ == "__main__":
    main()
