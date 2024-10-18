import socket
import threading
import struct


HEADER_SIZE = 16 #velkost v bajtoch


FLAG_SYN = 0b00000001       # SYN = 1
FLAG_SYN_ACK = 0b00000010   # SYN-ACK = 2
FLAG_ACK = 0b00000011       # ACK = 3
FLAG_FIN = 0b11111111       # FIN = 255



# I = 32-bit seq number, ack number
# H = 16-bit window, length
# B = 8-bit flags
# H = 16-bit checksum
# 3B = 24-bit offset - nech to je 16B dokopy
HEADER_FORMAT = '!IIHHBHB'




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

def create_header(seq_num, ack_num, window, length, flags, checksum):   #vytvori hlavicku protokolu
    offset = 0b00000000 #8bit offset
    return struct.pack(HEADER_FORMAT, seq_num, ack_num, window, length, flags, checksum, offset)



def parse_header(packet):   #funkcia na rozbalenie hlavicky
    return struct.unpack(HEADER_FORMAT, packet[:HEADER_SIZE])

def establish_connection():
    if not connection_established:
        header = create_header(0, 0,0, 0, FLAG_SYN, 0)  #prazdny packet s flagom SYN
        sock.sendto(header, (PEER_IP, PEER_PORT))
    else:
        print("uz sme spojeni")

def end_connection():
    global is_terminated, connection_established
    if connection_established:
        print("spojenie ukoncene!")
        header = create_header(0, 0, 0,0,FLAG_FIN, 0)   #prazdny packet s ukoncovacim flagom
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
    global is_terminated, connection_established

    while not is_terminated:
        try:
            sock.settimeout(1)  #kazdu sekundu sa program pozrie ci is_terminated neni uz false aby nebol zaseknuty v recvfrom() navzdy
            data, addr = sock.recvfrom(1024)  # Prijímanie až do 1024 bajtov
            body = data[HEADER_SIZE:]

            seq_num, ack_num, window, length, flags, checksum, offset = parse_header(data)


            if flags == FLAG_SYN and not connection_established:
                print(f"\nReceived SYN from {addr}. Sending SYN-ACK...")
                header = create_header( 0,0, 0,0, FLAG_SYN_ACK, 0)
                sock.sendto(header, addr)

            elif flags == FLAG_SYN_ACK and not connection_established:
                print(f"\nReceived SYN-ACK from {addr}. Sending ACK to complete handshake...")
                header = create_header(0, 0,0,0, FLAG_ACK, 0)
                sock.sendto(header, addr)
                connection_established = True
                print("Connection established!")

            elif flags == FLAG_ACK and not connection_established:
                print("Received ACK. Connection established!")
                connection_established = True

            elif connection_established:
                if flags == FLAG_FIN:   #ak dojde ukoncovaci packet
                    print("Spojenie ukoncene druhou stranou!")
                    connection_established = False



                if length > 0:
                    message = body.decode()
                    print(f"\nSpráva od {addr}: {message}")

        except socket.timeout: #kazdu sekundu sa znovu prejde cez loop
            continue
        except socket.error as e:
            if hasattr(e, 'winerror') and e.winerror == 10054:  #error ked este druhy pouzivatel nema nastavene porty
                connection_established = False #pre pripad ze jeden pouzivatel nevypne program spravne
                print("Druha strana este nieje zapojena!")
            else:
                print(f"Chyba pri prijímaní správy: {e}")


def main():
    global is_terminated
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()
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

if __name__ == "__main__":
    main()

