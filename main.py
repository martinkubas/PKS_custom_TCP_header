import socket
import threading
import struct
import headerStructure
import time

LOCAL_PORT = int(input("Zadajte váš lokálny port: "))
PEER_PORT = int(input("Zadajte port pre druhú stranu: "))


#LOCAL_IP = input("Zadajte vasu IP: ")
#PEER_IP =  input("Zadajte IP druheho PC: ")
LOCAL_IP = "127.0.0.1"
PEER_IP = "127.0.0.1"

# init udp socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LOCAL_IP, LOCAL_PORT))


is_terminated = False
connection_established = False

LAST_RECEIVED_MSG_TIME = time.time()
KEEPALIVE_INTERVAL = 5
KEEPALIVE_THRESHOLD = 15
def create_header(seq_num, ack_num, window, length, flags, checksum):   #vytvori hlavicku protokolu
    offset = 0b00000000 #8bit offset
    return struct.pack(headerStructure.HEADER_FORMAT, seq_num, ack_num, window, length, flags, checksum, offset)



def parse_header(packet):   #funkcia na rozbalenie hlavicky
    return struct.unpack(headerStructure.HEADER_FORMAT, packet[:headerStructure.HEADER_SIZE])

def establish_connection():
    if not connection_established:
        header = create_header(0, 0,0, 0, headerStructure.header_flags.SYN, 0)  #prazdny packet s flagom SYN
        sock.sendto(header, (PEER_IP, PEER_PORT))
    else:
        print("uz sme spojeni")

def end_connection():
    global is_terminated, connection_established
    if connection_established:
        print("spojenie ukoncene!")
        header = create_header(0, 0, 0,0,headerStructure.header_flags.FIN, 0)   #prazdny packet s ukoncovacim flagom
        sock.sendto(header, (PEER_IP, PEER_PORT))
        connection_established = False

    else:
        print("spojenie ani nebolo")


def send_messages(message): #posle text spravu peerovi
    global  connection_established

    if not connection_established:
        print("spojenie este nebolo nadviazane")
        return

    else:
        data = message.encode()
        header = create_header(0, 0, 0, len(data), 0, 0)
        sock.sendto(header+data, (PEER_IP, PEER_PORT))  #poslanie hlavicka + sprava klasicky text


def receive_messages(): #funkcia na prijmanie sprav
    global is_terminated, connection_established, LAST_RECEIVED_MSG_TIME

    while not is_terminated:
        try:
            sock.settimeout(1)  #kazdu sekundu sa program pozrie ci is_terminated neni uz false aby nebol zaseknuty v recvfrom() navzdy
            data, addr = sock.recvfrom(1024)  # Prijímanie až do 1024 bajtov
            body = data[headerStructure.HEADER_SIZE:]

            seq_num, ack_num, window, length, flags, checksum, offset = parse_header(data)


            if flags == headerStructure.header_flags.SYN and not connection_established:
                print(f"\nReceived SYN from {addr}. Sending SYN-ACK...")
                header = create_header( 0,0, 0,0, headerStructure.header_flags.SYN_ACK, 0)
                sock.sendto(header, addr)

            elif flags == headerStructure.header_flags.SYN_ACK and not connection_established:
                print(f"\nReceived SYN-ACK from {addr}. Sending ACK to complete handshake...")
                header = create_header(0, 0,0,0, headerStructure.header_flags.ACK, 0)
                sock.sendto(header, addr)
                connection_established = True
                LAST_RECEIVED_MSG_TIME = time.time()
                print("Connection established!")

            elif flags == headerStructure.header_flags.ACK and not connection_established:
                print("Received ACK. Connection established!")
                LAST_RECEIVED_MSG_TIME = time.time()
                connection_established = True

            elif connection_established:
                if flags == headerStructure.header_flags.FIN:   #ak dojde ukoncovaci packet
                    print("Spojenie ukoncene druhou stranou!")
                    connection_established = False

                elif flags == headerStructure.header_flags.KEEPALIVE:
                    header = create_header(0, 0,0, 0,headerStructure.header_flags.KEEPALIVE_ACK, 0)
                    sock.sendto(header, addr)
                    LAST_RECEIVED_MSG_TIME = time.time()
                    print("dostal som keepalive")

                elif flags == headerStructure.header_flags.KEEPALIVE_ACK:
                    print("dostal som keepalive ack.. teraz je allgood")
                    LAST_RECEIVED_MSG_TIME = time.time()

                if length > 0:
                    message = body.decode()
                    print(f"\nSpráva od {addr}: {message}")
                    LAST_RECEIVED_MSG_TIME = time.time()

        except socket.timeout: #kazdu sekundu sa znovu prejde cez loop
            continue
        except socket.error as e:
                print(f"Chyba pri prijímaní správy: {e}")

def keepalive():
    global connection_established
    while not is_terminated:
        if connection_established and time.time() - LAST_RECEIVED_MSG_TIME > KEEPALIVE_THRESHOLD:
            connection_established = False
            print("dlho mi nedosla ziadna sprava, spojenie povazujem za mrtve")
            break
        elif connection_established and time.time() - LAST_RECEIVED_MSG_TIME > KEEPALIVE_INTERVAL:
            header = create_header(0, 0, 0, 0, headerStructure.header_flags.KEEPALIVE, 0)
            sock.sendto(header, (PEER_IP, PEER_PORT))

        time.sleep(1)


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
          "umyselne poslat zlu spravu(nefunkcne) -> stlacte \"b\"\n"
          "uplne odist z programu -> stlacte \"ee\"\n"
          "!!!AKEKOLVEK INE ZNAKY SA POSLU AKO SPRAVA DRUHEMU POCITACU!!!"
          "\n------------------------------")

    while not is_terminated:
        choice = input()
        if choice == "f":
            #buducnost funkcie prinasa
            return 1
        elif choice == "e":
            end_connection()
        elif choice == "s":
            establish_connection()
        elif choice == "b":
            #nieco tu bude v buducnosti
            return 1
        elif choice == "ee":
            is_terminated = True
            if connection_established:  #ak su pripojeni - toto asi nebude treba ked bude implementovany keep-alive
                end_connection()
            receive_thread.join()

            break
        else:
            send_messages(choice)

    keepalive_thread.join()

if __name__ == "__main__":
    main()
