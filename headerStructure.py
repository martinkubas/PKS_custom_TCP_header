HEADER_SIZE = 16 #velkost v bajtoch
# I = 32-bit seq number, ack number
# H = 16-bit window, length
# B = 8-bit flags
# H = 16-bit checksum
# 3B = 24-bit offset - nech to je 16B dokopy
HEADER_FORMAT = '!IIHHBHB'


class Flags():
    def __init__(self):
        self.SYN =              0b00000001
        self.SYN_ACK =          0b00000010
        self.ACK =              0b00000011
        self.FIN =              0b11111111
        self.KEEPALIVE =        0b10000000
        self.KEEPALIVE_ACK =    0b10000001


header_flags = Flags()