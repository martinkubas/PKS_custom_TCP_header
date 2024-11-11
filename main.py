import socket
import threading
import struct
import headerStructure
import time

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
peer_seq_num = 1
last_acknowledged_seq = 0  # Tracks the last acknowledged sequence number

def create_header(seq_num, ack_num, window, length, flags, checksum):
    offset = 0b00000000  # 8-bit offset
    return struct.pack(headerStructure.HEADER_FORMAT, seq_num, ack_num, window, length, flags, checksum, offset)

def parse_header(packet):
    return struct.unpack(headerStructure.HEADER_FORMAT, packet[:headerStructure.HEADER_SIZE])

def establish_connection():
    global local_seq_num, connection_established
    if not connection_established:
        print("Initiating connection with SYN")
        header = create_header(0, 0, 0, 0, headerStructure.header_flags.SYN, 0)
        sock.sendto(header, (PEER_IP, PEER_PORT))
    else:
        print("Already connected")

def end_connection():
    global is_terminated, connection_established, local_seq_num
    if connection_established:
        print("Ending connection with FIN")
        header = create_header(local_seq_num, 0, 0, 0, headerStructure.header_flags.FIN, 0)
        sock.sendto(header, (PEER_IP, PEER_PORT))
        connection_established = False
        local_seq_num += 1
    else:
        print("No active connection to end")

def send_messages(message):
    global connection_established, local_seq_num, last_acknowledged_seq
    if not connection_established:
        print("Connection not yet established, cannot send message")
        return
    else:
        # Increment local sequence number for each new message sent
        local_seq_num += 1
        data = message.encode()
        # Send data without any flags, just with sequence and acknowledgment numbers
        header = create_header(local_seq_num, last_acknowledged_seq, 0, len(data), 0, 0)
        print(f"Sending message '{message}' with seq_num {local_seq_num} and ack_num {last_acknowledged_seq}")
        sock.sendto(header + data, (PEER_IP, PEER_PORT))

def receive_messages():
    global is_terminated, connection_established, LAST_RECEIVED_MSG_TIME, peer_seq_num, last_acknowledged_seq, local_seq_num

    while not is_terminated:
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(1024)
            body = data[headerStructure.HEADER_SIZE:]
            seq_num, ack_num, window, length, flags, checksum, offset = parse_header(data)

            print(f"Received packet with seq_num {seq_num}, ack_num {ack_num}, flags {flags}, length {length}, data {body.decode()}")

            if flags == headerStructure.header_flags.SYN and not connection_established:
                print(f"\nReceived SYN from {addr}. Sending SYN-ACK...")
                header = create_header(0, 0, 0, 0, headerStructure.header_flags.SYN_ACK, 0)
                sock.sendto(header, addr)


            elif flags == headerStructure.header_flags.SYN_ACK and not connection_established:
                print(f"\nReceived SYN-ACK from {addr}. Sending ACK to complete handshake...")
                header = create_header(0, 0, 0, 0, headerStructure.header_flags.ACK, 0)
                sock.sendto(header, addr)
                connection_established = True
                LAST_RECEIVED_MSG_TIME = time.time()
                print("Connection established!")

            elif flags == headerStructure.header_flags.ACK and not connection_established:
                print("Received ACK for handshake. Connection established!")
                LAST_RECEIVED_MSG_TIME = time.time()
                connection_established = True

            elif connection_established:
                if ack_num > last_acknowledged_seq:
                    print(f"Received ACK for sequence {ack_num}")
                    last_acknowledged_seq = ack_num
                    LAST_RECEIVED_MSG_TIME = time.time()

                if seq_num == peer_seq_num:
                    peer_seq_num += 1
                    if length > 0:
                        message = body.decode()
                        print(f"\nMessage from {addr}: {message}")
                        LAST_RECEIVED_MSG_TIME = time.time()

                        ack_header = create_header(local_seq_num, seq_num + 1, 0, 0, 0, 0)
                        sock.sendto(ack_header, addr)
                        print(f"Sent ACK for seq_num {seq_num + 1}")

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
            header = create_header(local_seq_num, last_acknowledged_seq, 0, 0, headerStructure.header_flags.KEEPALIVE, 0)
            sock.sendto(header, (PEER_IP, PEER_PORT))
        time.sleep(KEEPALIVE_INTERVAL)

def main():
    global is_terminated
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()
    keepalive_thread = threading.Thread(target=keepalive)
    keepalive_thread.start()

    print("------------------------\n"
          "Options: \n"
          "end connection -> press \"e\"\n"
          "establish connection -> press \"s\"\n"
          "exit program -> press \"ee\"\n"
          "!!!ANY OTHER CHARACTERS WILL BE SENT AS A MESSAGE TO THE PEER!!!"
          "\n------------------------------")

    while not is_terminated:
        choice = input()
        if choice == "e":
            end_connection()
        elif choice == "s":
            establish_connection()
        elif choice == "ee":
            is_terminated = True
            if connection_established:
                end_connection()
            receive_thread.join()
            break
        else:
            send_messages(choice)

    keepalive_thread.join()

if __name__ == "__main__":
    main()
