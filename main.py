import os
import socket
import threading
import time

from headerStructure import header_flags
from manPrint import print_man
from packetUtils import *
from connection import establish_connection, end_connection

LOCAL_PORT = int(input("Zadaj svoj port: "))
PEER_PORT = int(input("Zadaj kamaratov port: "))

LOCAL_IP = input("Zadaj svoju IP: ")
PEER_IP = input("Zadaj kamaratovu IP: ")
#LOCAL_IP = "127.0.0.1"
#PEER_IP = "127.0.0.1"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LOCAL_IP, LOCAL_PORT))

WINDOW_SIZE = 15
WINDOW_BASE = 0
MAX_FRAGMENT_SIZE = 1024 - HEADER_SIZE
fragment_size = 1008

current_file_location = ""

unacknowledged_packets = {}
acknowledgment_timeout = 2

is_terminated = False
connection_established = False
sent_FIN = False

last_received_msg_time = time.time()
KEEPALIVE_INTERVAL = 5
KEEPALIVE_THRESHOLD = 15

local_seq_num, peer_seq_num = 0, 0

def send_messages(message, bad_msg=False):
    global local_seq_num
    if not connection_established:
        print("Este neprebehlo spojenie, sprava sa neda odoslat")
        return
    if len(message) > fragment_size: #ak je sprava dlhsia ako max fragment size
        fragments = [message[i:i + fragment_size] for i in range(0, len(message), fragment_size)]

        i = 0
        while i < len(fragments):
            if not connection_established:  #pre pripad ze sa spojenie ukonci v strede posielania spravy
                print("spojenie sa prerusilo, koncim s posielanim spravy")
                break

            if (local_seq_num + 1) - WINDOW_BASE >= WINDOW_SIZE: #cakanie, kym sa window posunie
                time.sleep(0.1)
                continue

            ###poslanie fragmentu a ulozenie medzi unacknowledged packets dokym nedojde ack sprava###
            fragment = fragments[i].encode()
            local_seq_num += 1
            flag = header_flags.FRAG if i < len(fragments) - 1 else header_flags.FRAGSTOP   #flag FRAG kym to nieje posledny fragment, ak hej tak flag FRAGSTOP
            packet = create_packet(local_seq_num, peer_seq_num, len(fragment), flag, fragment, bad_msg)
            sock.sendto(packet, (PEER_IP, PEER_PORT))

            unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, flag, fragment)
            print(f"Posielam fragment spravy: {local_seq_num}, velkost: {len(fragment)} bytov")
            i += 1
    else:   #poslanie spravy v jednom packete
        local_seq_num += 1
        data = message.encode()
        packet = create_packet(local_seq_num, peer_seq_num, len(data), 0, data, bad_msg)
        unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, 0, data)
        print(f"Posielam spravu '{message}'")
        sock.sendto(packet, (PEER_IP, PEER_PORT))


def send_file(file_path, bad_file=False):
    global local_seq_num

    if not connection_established:
        print("Este neprebehlo spojenie, nemozem poslat subor")
        return

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    print(f"Posielam subor: {file_name} (velkost: {file_size} bytov)")

    ###poslanie START packetu###
    local_seq_num += 1
    start_packet = create_packet(local_seq_num, peer_seq_num, len(file_name.encode()), header_flags.START,
                                 file_name.encode())
    sock.sendto(start_packet, (PEER_IP, PEER_PORT))
    unacknowledged_packets[local_seq_num] = (
    time.time(), local_seq_num, peer_seq_num, header_flags.START, file_name.encode())

    with open(file_path, 'rb') as file:
        data = file.read(fragment_size)
        while data:
            if not connection_established:
                print("Pripojenie sa zrusilo, koncim s prenosom suboru")
                break

            if (local_seq_num + 1) - WINDOW_BASE >= WINDOW_SIZE:
                time.sleep(0.1)
                continue
            local_seq_num += 1
            packet = create_packet(local_seq_num, peer_seq_num, len(data), 0, data, bad_file)
            sock.sendto(packet, (PEER_IP, PEER_PORT))

            unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, 0, data)
            print(f"Poslany fragment suboru:{file_name}, s seq_num: {local_seq_num}, velkost: {len(data)} bytov")
            data = file.read(fragment_size)
    ###poslanie STOP packetu, indikujuci koniec suboru###
    local_seq_num += 1
    stop_packet = create_packet(local_seq_num, peer_seq_num, 0, header_flags.STOP, b'')
    sock.sendto(stop_packet, (PEER_IP, PEER_PORT))
    print("Cely subor bol odoslany")
    unacknowledged_packets[local_seq_num] = (time.time(), local_seq_num, peer_seq_num, header_flags.STOP, b'')


def receive_file(start_seq_num, file_name="received_file.png"):
    global peer_seq_num, last_received_msg_time
    received_data = {}
    stop_seq_num = None
    received_stop = False

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            body = data[HEADER_SIZE:]
            seq_num, ack_num, length, flags, checksum = parse_header(data)

            #porovnanie checksumu#
            checksum_calc_header = create_header(seq_num, ack_num, length, flags, 0)
            calculated_checksum = calculate_crc(checksum_calc_header + body)
            if calculated_checksum != checksum:
                print(f"Chyba v checsume v packete: {seq_num}. Posielam NACK.")
                nack_packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.NACK, b'')
                sock.sendto(nack_packet, addr)
                continue

            #ci je packet medzi zaciatocnym a konecnym packetom suboru
            if seq_num >= start_seq_num and (stop_seq_num is None or seq_num <= stop_seq_num):
                received_data[seq_num] = body

                if seq_num >= peer_seq_num:
                    peer_seq_num = seq_num + 1

                print(f"Dostal som fragment suboru so seq_num: {seq_num}, velkost: {len(body)} bytov")
                last_received_msg_time = time.time()

                #poslanie ack packetu
                ack_packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.ACK, b'')
                sock.sendto(ack_packet, addr)
                print(f"Poslal som ACK pre seq_num {seq_num + 1}")

                # zaznacenie seq cisla posledneho packetu
                if flags == header_flags.STOP:
                    print("Dostal som posledny fragment suboru")
                    received_stop = True
                    stop_seq_num = seq_num

            # loop sa zastavi len ked dostal stop fragment a vsetky packety boli prijate
            if received_stop:
                missing_fragments = set(range(start_seq_num + 1, stop_seq_num + 1)) - set(received_data.keys()) #dostal stop a vsetky fragmenty pred
                if missing_fragments:
                    print(f"Cakam na chybajuce packety: {missing_fragments}")
                    time.sleep(0.1)
                    continue


                print("Vsetky fragmenty dorucene. Ukladam subor.")
                break
        except socket.timeout:
            continue

    full_path = os.path.join(current_file_location, file_name)
    with open(full_path, 'wb') as file:
        time.sleep(0.1)
        for i in sorted(received_data.keys()):
            file.write(received_data[i])

    print(f"Uspesne ulozenie suboru. Velkost: {os.path.getsize(file_name)} bytov. Cesta: {full_path}")
    return


def receive_messages():
    global is_terminated, connection_established, last_received_msg_time, peer_seq_num, local_seq_num,  WINDOW_BASE
    received_message = {}
    start_seq_num = None
    stop_seq_num = None
    received_stop = False
    while not is_terminated:
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(1024)
            body = data[HEADER_SIZE:]
            seq_num, ack_num, length, flags, checksum = parse_header(data)


            checksum_calc_header = create_header(seq_num, ack_num, length, flags, 0)
            calculated_checksum = calculate_crc(checksum_calc_header + body)

            if calculated_checksum != checksum:
                print(f"Chyba v checsume v packete: {seq_num}. Posielam NACK.")
                nack_packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.NACK, b'')
                sock.sendto(nack_packet, addr)
                continue

            if flags == header_flags.FIN:
                print("Dostal som FIN. Posielam FIN_ACK pre ukoncenie spojenia")
                connection_established = False
                packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.FIN_ACK, b'')
                sock.sendto(packet, addr)
                print("Spojenie ukoncene!")

            elif flags == header_flags.FIN_ACK and sent_FIN:
                connection_established = False
                print("dostal som FIN_ACK spojenie ukoncene")
                local_seq_num, peer_seq_num  = 0, 0
                WINDOW_BASE = 0

            elif flags == header_flags.SYN and not connection_established:
                print(f"\nDostal som SYN od {addr}. Posielam SYN-ACK...")
                peer_seq_num = seq_num + 1
                local_seq_num += 1
                packet = create_packet(local_seq_num, peer_seq_num, 0, header_flags.SYN_ACK, b'')
                sock.sendto(packet, addr)


            elif flags == header_flags.SYN_ACK and not connection_established:
                print(f"\nDostal som SYN-ACK od {addr}. Posielam ACK na dokoncenie handshaku...")
                peer_seq_num = seq_num + 1
                local_seq_num += 1
                packet = create_packet(local_seq_num, peer_seq_num,0, header_flags.ACK, b'')
                sock.sendto(packet, addr)
                connection_established = True
                last_received_msg_time = time.time()
                print("Spojenie nadviazane!")

            elif flags == header_flags.ACK and not connection_established:
                peer_seq_num = seq_num + 1
                print("Dostal som ACK pre handshake. Spojenie nadviazane!")
                last_received_msg_time = time.time()
                connection_established = True

            elif flags == header_flags.ACK and connection_established:
                if seq_num >= peer_seq_num:
                    peer_seq_num = seq_num + 1

                print(f"Dostal som ACK pre seq: {ack_num}")
                last_received_msg_time = time.time()

                #vymazanie z evidencie neprijatych packetov
                if ack_num - 1 in unacknowledged_packets:
                    del unacknowledged_packets[ack_num - 1]

                # update WINDOW_BASE kde window base je najmensie seq cislo
                # neuznaneho packetu pricom vsetky packety pred nim su uz uznane
                if unacknowledged_packets:
                    min_unacknowledged = min(unacknowledged_packets.keys())

                    WINDOW_BASE = min_unacknowledged
                else:
                    WINDOW_BASE = ack_num

            elif flags == header_flags.NACK and connection_established:
                #ak je nack medzi neuznanymi packetmi
                if ack_num - 1 in unacknowledged_packets:
                    print(f"Dostal som NACK pre seq_num: {ack_num - 1}, znovu posielam packet.")

                    ttimestamp, sseq_num, aack_num, fflags, ddata = unacknowledged_packets[ack_num - 1]
                    packet = create_packet(sseq_num, aack_num, len(ddata), fflags, ddata)
                    sock.sendto(packet, addr)
                    #update casu poslania, nech sa to neposle hned znovu
                    unacknowledged_packets[ack_num - 1] = (time.time(), sseq_num, aack_num, fflags, ddata)


            elif connection_established:
                if flags == header_flags.START:
                    print(f"Zacinam prijmat subor: {body.decode()}")
                    ack_packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.ACK, b'')
                    sock.sendto(ack_packet, addr)

                    receive_file(seq_num, body.decode()) #prepnutie na prijmanie suboru
                    continue

                if flags == header_flags.KEEPALIVE:
                    print("Dostal som KEEPALIVE posielam KEEPALIVE_ACK")
                    packet = create_packet(0, 0, 0, header_flags.KEEPALIVE_ACK, b'')
                    sock.sendto(packet, addr)
                    last_received_msg_time = time.time()

                elif flags == header_flags.KEEPALIVE_ACK:
                    print("Dostal som KEEPALIVE_ACK")
                    last_received_msg_time = time.time()


                elif flags == header_flags.FRAG:
                    if stop_seq_num is None or seq_num <= stop_seq_num:
                        received_message[seq_num] = body

                    if start_seq_num is None or seq_num < start_seq_num :   #ak dojde najprv druhy packet
                        start_seq_num = seq_num

                    if seq_num >= peer_seq_num:
                        peer_seq_num = seq_num + 1

                    print(f"Dostal som fragment spravy {seq_num}, velkost: {len(body)} bytov")
                    last_received_msg_time = time.time()

                    ack_packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.ACK, b'')
                    sock.sendto(ack_packet, addr)
                    print(f"Poslal som ACK pre seq_num {seq_num + 1}")
                    ##ak dostal stop skorej ako celu spravu##
                    if received_stop and set(range(start_seq_num + 1, stop_seq_num + 1)) <= set(received_message.keys()):

                        print(f"\nCela fragmentova sprava od {addr}:",''.join(received_message[seq].decode() for seq in sorted(received_message.keys())), "\n")
                        received_message = {}
                        start_seq_num, stop_seq_num, received_stop = None, None, False

                elif flags == header_flags.FRAGSTOP:
                    print("Dostal som posledny fragment")
                    received_stop = True
                    stop_seq_num = seq_num
                    received_message[seq_num] = body

                    ack_packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.ACK, b'')
                    sock.sendto(ack_packet, addr)

                   #ak dostane Poslednu spravu ako poslednu a vsetky pred tym uz su prijate
                    if received_stop and set(range(start_seq_num + 1, stop_seq_num + 1)) <= set(received_message.keys()):
                        print(f"\nCela fragmentovana sprava od {addr}:",''.join(received_message[seq].decode() for seq in sorted(received_message.keys())), "\n")

                        received_message = {}
                        start_seq_num, stop_seq_num, received_stop = None, None, False

                elif seq_num <= peer_seq_num and seq_num != 0:  #prijatie normalnej spravy v jednom packete
                    if seq_num == peer_seq_num:
                        peer_seq_num = seq_num + 1

                    if length > 0:
                        message = body.decode()
                        print(f"\nSprava od {addr}: {message}\n")
                        last_received_msg_time = time.time()

                        # Send ACK for received packet
                        ack_packet = create_packet(local_seq_num, seq_num + 1, 0, header_flags.ACK, b'')
                        sock.sendto(ack_packet, addr)
                        print(f"Poslal som ACK pre seq_num: {seq_num + 1}")

        except socket.timeout:
            continue
        except socket.error as e:
            print(f"Error pri prijmani spravy: {e}")

def handle_unacknowledged_packets():
    global unacknowledged_packets
    while not is_terminated:
        if not connection_established:
            unacknowledged_packets = {}
            time.sleep(1)
            continue

        current_time = time.time()
        for seq_num, (timestamp, seq_num, ack_num, flags, data) in list(unacknowledged_packets.items()):
            if current_time - timestamp > acknowledgment_timeout:
                print(f"Znovu posielam packet so seq_num: {seq_num}")
                packet = create_packet(seq_num, ack_num, len(data), flags, data)
                sock.sendto(packet, (PEER_IP, PEER_PORT))
                unacknowledged_packets[seq_num] = (current_time, seq_num, ack_num, flags, data)
        time.sleep(0.5)

def keepalive():
    global connection_established, local_seq_num, peer_seq_num, unacknowledged_packets, WINDOW_BASE
    while not is_terminated:
        ###ak je posledna prijata sprava neskor, ako je povolene###
        if connection_established and time.time() - last_received_msg_time > KEEPALIVE_THRESHOLD:
            connection_established = False
            print("Dlho som nic nedostal. Spojenie je ukoncene")
            local_seq_num, peer_seq_num = 0, 0
            WINDOW_BASE = 0
            break
        ###ak je posledna prijata sprava neskor, ako KEEPALIVE interval###
        elif connection_established and time.time() - last_received_msg_time > KEEPALIVE_INTERVAL:
            print("Posielam keepalive")
            packet = create_packet(0, 0, 0, header_flags.KEEPALIVE, b'')
            sock.sendto(packet, (PEER_IP, PEER_PORT))

        time.sleep(KEEPALIVE_INTERVAL)



def main():
    global is_terminated, fragment_size, current_file_location, local_seq_num, sent_FIN

    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()

    keepalive_thread = threading.Thread(target=keepalive)
    keepalive_thread.start()

    unacknowledged_thread = threading.Thread(target=handle_unacknowledged_packets)
    unacknowledged_thread.start()

    print_man() #vypisanie manualu na pouzivanie

    while not is_terminated:
        choice = input()
        if choice == "man":
            print_man()
        elif choice[:4] == "cfrs":  # change fragment size
            if 0 < int(choice[5:]) <= MAX_FRAGMENT_SIZE:
                fragment_size = int(choice[5:])
                print(f"Velkost fragmentu: {fragment_size}")
            else:
                print(f"velkost fragmentu nieje v limite (1, {MAX_FRAGMENT_SIZE})")

        elif choice[:3] == "cfl":  # change file location
            new_location = choice[4:].strip()
            if os.path.isdir(new_location):
                current_file_location = new_location
                print(f"Miesto ulozenia zmenene na: {current_file_location}")
            else:
                print("Taketo miesto neexistuje. Miesto ulozenia sa nemeni")

        elif choice[:2] == "bm":
            send_messages(choice[3:], bad_msg=True)
        elif choice[:2] == "bf":
            if not os.path.isfile(choice[3:]):
                print("Subor sa nenasiel!")
                continue
            send_file(choice[3:], bad_file=True)

        elif choice[0] == 'm':
            send_messages(choice[2:])

        elif choice[0] == 'f':
            if not os.path.isfile(choice[2:]):
                print("Subor sa nenasiel!")
                continue
            send_file(choice[2:])
        elif choice == "ee":
            is_terminated = True
            local_seq_num, sent_FIN = end_connection(sock, PEER_IP, PEER_PORT, local_seq_num, connection_established, sent_FIN)
            receive_thread.join()
            break
        elif choice == "e":
            local_seq_num, sent_FIN = end_connection(sock, PEER_IP, PEER_PORT, local_seq_num, connection_established, sent_FIN)
        elif choice == "s":
            local_seq_num = establish_connection(sock, PEER_IP, PEER_PORT, local_seq_num, connection_established)
        else:
            print("\nNerozpoznany command, napiste \"man\" pre vypisanie manualu\n")


    keepalive_thread.join()
    unacknowledged_thread.join()

if __name__ == "__main__":
    main()