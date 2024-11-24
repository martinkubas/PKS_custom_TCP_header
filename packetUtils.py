import crcmod
import struct
from headerStructure import HEADER_SIZE, HEADER_FORMAT

def calculate_crc(data):
    crc16_func = crcmod.predefined.mkCrcFun('crc-16')
    return crc16_func(data)

def create_header(seq_num, ack_num, length, flags, checksum):
    offset1 = 0b00000000
    offset2 = 0b00000000
    offset3 = 0b00000000
    return struct.pack(HEADER_FORMAT, seq_num, ack_num, length, flags, checksum, offset1, offset2,offset3)

def create_packet(seq_num, ack_num, length, flags, data, bad_msg=False):
    checksum = 0
    header = create_header(seq_num, ack_num, length, flags, checksum)
    packet = header + data
    checksum = calculate_crc(packet)
    if bad_msg:
        checksum += 1
    checksum_header = create_header(seq_num, ack_num, length, flags, checksum)
    return checksum_header + data

def parse_header(packet):
    seq_num, ack_num, length, flags, checksum, offset1, offset2, offset3 = struct.unpack(HEADER_FORMAT,
                                                                            packet[:HEADER_SIZE])
    return seq_num, ack_num, length, flags, checksum