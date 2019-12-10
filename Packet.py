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
    tcp_flag = ""
    arp_op = ""
    arp_src_ip = ""
    arp_dst_ip = ""
    icmp_type = ""
    tftp_type = -1

    def __init__(self, data):
        self.data = bytes(data)
        self.source_mac = self.set_source_mac(6)
        self.dest_mac = self.set_dest_mac(0)
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
            self.source_ip = self.setSourceIP(26)
            self.dest_ip = self.setDestIP(30)
            self.set_l3_type()

        if self.l2_type == "ARP":
            arp_op = int.from_bytes(self.data[20:22], 'big')
            if arp_op == 1:
                self.arp_op = "Request"
            elif arp_op == 2:
                self.arp_op = "Reply"

            if int.from_bytes(self.data[16:18], 'big') == 2048:
                self.arp_src_mac = self.set_source_mac(22)
                self.arp_dst_mac = self.set_dest_mac(32)
                self.arp_src_ip = self.setSourceIP(28)
                self.arp_dst_ip = self.setDestIP(38)


    def set_l3_type(self):
        csv_file = csv.reader(open('ipv4-numbers.csv', "r"), delimiter=",")
        next(csv_file)
        for row in csv_file:
            if (int(row[0]) == self.data[23]):
                self.l3_type = row[1]
                break
        if self.l3_type == "TCP" or self.l3_type == "UDP":
            if self.l3_type == "TCP":
                l4_header_start = 14 + 4 * int(bin(self.data[14])[4:], 2)
                flag = int(self.data[l4_header_start + 13])
                if (flag & 1) != 0:
                    self.tcp_flag += " FIN"
                if (flag & 2 != 0):
                    self.tcp_flag += " SYN"
                if (flag & 4 != 0):
                    self.tcp_flag += " RST"
                if (flag & 8 != 0):
                    self.tcp_flag += " PSH"
                if (flag & 16 != 0):
                    self.tcp_flag += " ACK"
                if (flag & 32 != 0):
                    self.tcp_flag += " URG"
                if (flag & 64 != 0):
                    self.tcp_flag += " ECE"
                if (flag & 128 != 0):
                    self.tcp_flag += " CWR"
            self.set_l4_type()
        if self.l3_type == "ICMP":
            l4_header_start = 14 + 4 * int(bin(self.data[14])[4:], 2)
            type = int(self.data[l4_header_start])
            code = int(self.data[l4_header_start+1])
            if type == 0:
                self.icmp_type = "Echo Reply"
            elif type == 8:
                self.icmp_type = "Echo Request"
            elif type == 3:
                self.icmp_type = "Destination unreachable"
            elif type == 11:
                self.icmp_type = "TTL Exceeded"


    def set_l4_type(self):
        csv_file = csv.reader(open('port-numbers.csv', "r"), delimiter=",")
        l4_header_start = 14 + 4*int(bin(self.data[14])[4:], 2)
        self.source_port = int.from_bytes(self.data[l4_header_start:l4_header_start+2], 'big')
        self.dest_port = int.from_bytes(self.data[l4_header_start+2:l4_header_start+4], 'big')
        next(csv_file)
        for row in csv_file:
            if ("-" not in row[1] and row[0] != "" and row[1] != "" and int(row[1]) == self.source_port) or ("-" not in row[1] and row[0] != "" and row[1] != "" and int(row[1]) == self.dest_port):
                if row[2] == self.l3_type.lower():
                    self.l4_type = row[0]
                    if self.l4_type == "router":
                        self.l4_type = "RIP"
                    if self.l4_type == "tftp":
                        self.tftp_type = int.from_bytes(self.data[l4_header_start+8:l4_header_start+10], 'big')
                    break

    def set_ieee_type(self):
        if(int.from_bytes(self.data[14:16], 'big') == 65535):
            self.type = 1
        elif(int.from_bytes(self.data[14:16], 'big') == 43690):
            self.type = 2
            self.header_len += 5
            ethertype = int.from_bytes(self.data[20:22], "big")
            csv_file = csv.reader(open('ieee-numbers.csv', "r"), delimiter=",")
            next(csv_file)
            for row in csv_file:
                if (row[0] == ''):
                    continue

                if (int(row[0]) == ethertype):
                    self.l2_type = row[4]
                    break

        else:
            self.type = 3
            csv_file = csv.reader(open('ieee-802-LLC.csv', "r"), delimiter=",")
            next(csv_file)
            for row in csv_file:
                if (int(self.data[14]) == int(row[2])):
                    self.l2_type = row[3]
                    break

    def set_type(self):
        if(int.from_bytes(self.data[12:14], 'big') > 1536) :
            self.type = 0 # is Ethernet II
        else:
            self.header_len += 3
            self.set_ieee_type()

    def set_source_mac(self, pos):
        source_mac = ""
        for i in range(6):
            source_mac += str(format(self.data[pos], '02x')) + ":"
            pos+=1
        source_mac = source_mac[:-1]
        return source_mac

    def set_dest_mac(self, pos):
        dest_mac = ""
        for i in range(6):
            dest_mac += str(format(self.data[pos], '02x')) + ":"
            pos+=1
        dest_mac = dest_mac[:-1]
        return dest_mac

    def set_ipv6_addr(self, pos):
        ip = ""
        for i in range(8):
            ip += str(format(int.from_bytes(self.data[pos:pos+2], "big"), '04x')) + ":"
            pos += 2

    def get_type(self):
        return self.type

    def get_source_mac(self):
        return self.source_mac

    def get_dest_mac(self):
        return self.dest_mac

    def get_source_address(self):
        if self.source_ip == "":
            return self.source_mac
        return self.source_ip

    def get_dest_address(self):
        if self.dest_ip == "":
            return self.dest_mac
        return self.dest_ip

    def get_protocol(self):
        if self.l4_type != "":
            if self.l3_type != "TCP":
                return self.l4_type
            else:
                if self.tcp_flag == " PSH ACK":
                    return self.l4_type
        if self.l3_type != "":
            return self.l3_type
        if self.l2_type != "":
            return self.l2_type

        if self.type == 0 :
            return "Ethernet II"
        elif self.type == 1:
            return "IEEE 802.3 Raw"
        elif self.type == 2:
            return "IEEE 802.3 LLC + SNAP"
        else :
            return "IEEE 802.3 LLC"

    def get_contents_hex(self):
        data = binascii.hexlify(bytearray(self.data))
        data = b" ".join(data[i:i + 2] for i in range(0, len(data), 2))
        data = b"\n".join(data[i:i + 48] for i in range(0, len(data), 48))
        return data

    def setSourceIP(self, k):
        source_ip = ""
        for i in range(4):
            source_ip += str(self.data[k+i]) + "."
        source_ip = source_ip[:len(source_ip)-1]
        return source_ip

    def setDestIP(self, k):
        dest_ip = ""
        for i in range(4):
            dest_ip += str(self.data[k+i]) + "."
        dest_ip = dest_ip[:len(dest_ip)-1]
        return dest_ip

    def getSourceIP(self):
        return self.source_ip

    def getDestIP(self):
        return self.dest_ip

    def get_l3type(self):
        return self.l3_type

    def tcp_parse(self):
        res = {}
        l3_header_start = 14 + 4 * int(bin(self.data[14])[4:], 2)
        res["seq"] = int.from_bytes(self.data[l3_header_start + 4:l3_header_start + 8], 'big')
        if "ACK" in self.tcp_flag:
            res["ack"] = int.from_bytes(self.data[l3_header_start + 8:l3_header_start + 12], 'big')
        res["win"] = int.from_bytes(self.data[l3_header_start + 14:l3_header_start + 16], 'big')
        return res


