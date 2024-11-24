from packetUtils import create_packet
from headerStructure import header_flags

def establish_connection(sock, PEER_IP, PEER_PORT, local_seq_num, connection_established):
    if not connection_established:
        print("Zacinam spojenie cez SYN")
        local_seq_num += 1
        packet = create_packet(local_seq_num, 0, 0, header_flags.SYN, b'')
        sock.sendto(packet, (PEER_IP, PEER_PORT))
        return local_seq_num
    else:
        print("Uz som pripojeny")
        return local_seq_num


def end_connection(sock, PEER_IP, PEER_PORT, local_seq_num, connection_established, sent_FIN):
    if not connection_established:
        print("Ziadne pripojenie ani nieje")
        return local_seq_num, sent_FIN

    print("Koncim spojenie pomocou FIN")
    local_seq_num += 1
    packet = create_packet(local_seq_num, 0, 0, header_flags.FIN, b'')
    sock.sendto(packet, (PEER_IP, PEER_PORT))
    sent_FIN = True
    return local_seq_num, sent_FIN