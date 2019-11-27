import binascii
import csv

class Packet:
    type = 0
    source_mac = ""
    dest_mac = ""
    header_len = 14
    l2_type = ""
    ethertype = 0
    source_ip = ""
    dest_ip = ""
    l3_type = ""
    l4_type = ""
    source_port = 0
    dest_port = 0

    def __init__(self, data):
        self.data = bytes(data)
        self.set_source_mac()
        self.set_dest_mac()
        self.set_type()
        self.set_l2_type()

    def set_l2_type(self):
        csv_file = csv.reader(open('ieee-numbers.csv', "r"), delimiter=",")
        if self.type == 0:
            ethertype = int.from_bytes(self.data[12:14], 'big')
            self.ethertype = ethertype
        else:
            return

        next(csv_file)
        for row in csv_file:
            if(row[0] == ''):
                continue

            if(int(row[0]) == ethertype):
                self.l2_type = row[4]
                break

        if ethertype == 2048:
            self.setSourceIP()
            self.setDestIP()
            self.set_l3_type()

    def set_l3_type(self):
        csv_file = csv.reader(open('ipv4-numbers.csv', "r"), delimiter=",")
        next(csv_file)
        for row in csv_file:
            if (int(row[0]) == self.data[23]):
                self.l3_type = row[1]
                break
        if self.l3_type == "TCP" or self.l3_type == "UDP":
            self.set_l4_type()

    def set_l4_type(self):
        csv_file = csv.reader(open('port-numbers.csv', "r"), delimiter=",")
        l4_header_start = 14 + 4*int(bin(self.data[14])[4:], 2)
        self.source_port = int.from_bytes(self.data[l4_header_start:l4_header_start+2], 'big')
        self.dest_port = int.from_bytes(self.data[l4_header_start+2:l4_header_start+4], 'big')
        next(csv_file)
        for row in csv_file:
            if ("-" not in row[1] and row[0] != "" and row[1] != "" and int(row[1]) == self.source_port) or ("-" not in row[1] and row[0] != "" and row[1] != "" and int(row[1]) == self.dest_port):
                self.l4_type = row[0]
                break

    def set_ieee_type(self):
        if(int.from_bytes(self.data[14:16], 'big') == 65535):
            self.type = 1
        elif(int.from_bytes(self.data[14:16], 'big') == 43690):
            self.type = 2
            self.header_len += 5
        else:
            self.type = 3

    def set_type(self):
        if(int.from_bytes(self.data[12:14], 'big') > 1536) :
            self.type = 0 # is Ethernet II
        else:
            self.header_len += 3
            self.set_ieee_type()

    def set_source_mac(self):
        pos = 6
        source_mac = ""
        for i in range(6):
            source_mac += str(format(self.data[pos], '02x')) + ":"
            pos+=1
        source_mac = source_mac[:-1]
        self.source_mac = source_mac

    def set_dest_mac(self):
        pos = 0
        dest_mac = ""
        for i in range(6):
            dest_mac += str(format(self.data[pos], '02x')) + ":"
            pos+=1
        dest_mac = dest_mac[:-1]
        self.dest_mac = dest_mac

    def get_type(self):
        return self.type

    def get_source_mac(self):
        return self.source_mac

    def get_dest_mac(self):
        return self.dest_mac

    def get_contents_hex(self):
        data = binascii.hexlify(bytearray(self.data))
        data = b" ".join(data[i:i + 2] for i in range(0, len(data), 2))
        data = b"\n".join(data[i:i + 48] for i in range(0, len(data), 48))
        return data

    def setSourceIP(self):
        for i in range(4):
            self.source_ip += str(self.data[26+i]) + ":"
        self.source_ip = self.source_ip[:len(self.source_ip)-1]

    def setDestIP(self):
        for i in range(4):
            self.dest_ip += str(self.data[30+i]) + ":"
        self.dest_ip = self.dest_ip[:len(self.dest_ip)-1]

    def getSourceIP(self):
        return self.source_ip

    def getDestIP(self):
        return self.dest_ip

    def get_l3type(self):
        return self.l3_type


