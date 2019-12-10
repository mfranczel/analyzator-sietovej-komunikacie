from PySide2.QtGui import QColor
from PySide2.QtWidgets import QTableWidgetItem

from Packet import Packet
import operator

class Analyser:
    ips = {}
    packets = []
    def __init__(self, file_content):
        self.ips = {}
        self.packets = []
        self.file_content = file_content
        for packet in self.file_content:
            my_packet = Packet(packet)
            self.packets.append(my_packet)
            src_already_in_list = False
            dst_already_in_list = False
            for a in self.ips:
                if a == my_packet.source_ip:
                    src_already_in_list = True

            if not src_already_in_list and my_packet.source_ip != "":
                self.ips[my_packet.source_ip] = 1
            elif src_already_in_list and my_packet.source_ip != "":
                self.ips[my_packet.source_ip] += 1

    def get_info(self, i, mac, l1, l2, l3, l4, IP, ports):
        i -= 1
        packet = self.packets[i]
        content = ""
        if l1:
            content += "L1: "
            if (packet.get_type() == 0):
                content += "Ethernet II\n"
            else:
                content += "IEEE 802.3 "
                type = packet.get_type()
                if (type == 1):
                    content += "Raw\n"
                elif (type == 2):
                    content += "with LLC and SNAP\n"
                else:
                    content += "with LLC\n"
        if mac:
            content += "Source MAC: " + packet.get_source_mac() + "\n"
            content += "Dest MAC: " + packet.get_dest_mac() + "\n"

        content += "Frame size: " + str(len(packet.data)) + "\nTransfer size: "
        if (len(packet.data) < 60):
            content += str(64)
        else:
            content += str(len(packet.data) + 4)
        content += "\n"

        if l2 and packet.l2_type != "":
            content += "L2: "
            content += packet.l2_type + "\n"
        if IP and packet.ethertype == 2048:
            content += "Source IP: " + packet.getSourceIP() + "\n"
            content += "Dest IP: " + packet.getDestIP() + "\n"
        if l3 and packet.l3_type != "":
            content += "L3: "
            content += packet.l3_type + "\n"

        if ports and packet.source_port != 0:
            content += "Source port: " + str(packet.source_port) + "\n"
            content += "Dest port: " + str(packet.dest_port) + "\n"

        if l4 and packet.l4_type != "":
            content += "L4: "
            content += packet.l4_type + "\n"

        if packet.l2_type == "ARP":
            content += "Sender MAC address: " + packet.arp_src_mac + "\n"
            content += "Receiver MAC address: " + packet.arp_dst_mac + "\n"
            content += "Sender IP: " + packet.arp_src_ip + "\n"
            content += "Target IP: " + packet.arp_dst_ip + "\n"

        content += str(packet.get_contents_hex().decode())[0:len(packet.get_contents_hex())] + "\n"
        return content


    def get_IPs(self):
        content = ""
        sorted(self.ips.items(), key=lambda x: x[1], reverse=True)
        for a in self.ips:
            content += a + "\n"
        content += "Most active sender:\n"
        content += str(list(self.ips)[0]) + " - " +str(list(self.ips.values())[0])
        return content

    def get_hex(self, mac, l1, l2, l3, l4, IP, ports):
        content = ""
        counter = 0

        for packet in self.packets:
            my_packet = packet
            a = len(packet.data)
            counter += 1
            content += str(counter) + "\n"

            if l1 == True:
                content += "L1: "
                if(my_packet.get_type() == 0):
                    content += "Ethernet II\n"
                else:
                    content += "IEEE 802.3 "
                    type = my_packet.get_type()
                    if(type == 1):
                        content += "Raw\n"
                    elif(type == 2):
                        content += "with LLC and SNAP\n"
                    else:
                        content += "with LLC\n"

            if mac == True:
                content += "Source MAC: " + my_packet.get_source_mac() + "\n"
                content += "Dest MAC: " + my_packet.get_dest_mac() + "\n"

            content += "Frame size: " + str(a) + "\nTransfer size: ";
            if(a < 60) :
                content += str(64)
            else:
                content += str(a+4)
            content += "\n"

            if l2 == True and my_packet.l2_type != "":
                content += "L2: "
                content += my_packet.l2_type + "\n"

            if IP == True and my_packet.ethertype == 2048:
                content += "Source IP: " + my_packet.getSourceIP() + "\n"
                content += "Dest IP: " + my_packet.getDestIP() + "\n"

            if l3 == True and my_packet.l3_type != "":
                content += "L3: "
                content += my_packet.l3_type + "\n"

            if ports == True and my_packet.source_port != 0:
                content += "Source port: " + str(my_packet.source_port) + "\n"
                content += "Dest port: " + str(my_packet.dest_port) + "\n"

            if l4 == True and my_packet.l4_type != "":
                content += "L4: "
                content += my_packet.l4_type + "\n"


            src_already_in_list = False
            dst_already_in_list = False

            for a in self.ips:
                if a == my_packet.source_ip:
                    src_already_in_list = True

            if not src_already_in_list and my_packet.source_ip != "":
                self.ips[my_packet.source_ip] = 1
            elif src_already_in_list and my_packet.source_ip != "":
                self.ips[my_packet.source_ip] += 1

            content += str(my_packet.get_contents_hex().decode())[0:len(my_packet.get_contents_hex())] + "\n"

        content += "IP's:\n"
        for a in self.ips:
            content += a + "\n"
        content += "Most active sender: " + max(self.ips.items(), key=operator.itemgetter(1))[0] + "\n"


        return content

    def filter_tcp(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)
        tcp_packets = []
        done = []
        for packet in self.packets:
            if packet.l3_type == "TCP":
                tcp_packets.append(packet)
        l = 0
        a = True
        for j in range(len(tcp_packets)):
            if (tcp_packets[j] not in done):
                tcp_flags = []
                for k in range(j, len(tcp_packets)):

                    if ((tcp_packets[j].source_port == tcp_packets[k].source_port and tcp_packets[j].dest_port == tcp_packets[k].dest_port) or (tcp_packets[j].source_port == tcp_packets[k].dest_port and tcp_packets[j].dest_port == tcp_packets[k].source_port)):

                        done.append(tcp_packets[k])
                        tcp_flags.append(tcp_packets[k].tcp_flag)

                        ports = str(tcp_packets[k].source_port) + " -> " + str(tcp_packets[k].dest_port)
                        tcp_info = tcp_packets[k].tcp_parse()
                        ports += " [" + tcp_packets[k].tcp_flag + "]"
                        ports += " Seq=" + str(tcp_info["seq"])
                        if "ack" in tcp_info.keys():
                            ports += " Ack=" + str(tcp_info["ack"])
                        ports += " Win=" + str(tcp_info["win"])

                        index = QTableWidgetItem(str(self.packets.index(tcp_packets[k]) + 1))
                        src = QTableWidgetItem(tcp_packets[k].get_source_address())
                        dest = QTableWidgetItem(tcp_packets[k].get_dest_address())
                        proto = QTableWidgetItem(tcp_packets[k].get_protocol())
                        info = QTableWidgetItem(ports)

                        if a:
                            color = QColor(69, 34, 34)
                        else:
                            color = QColor(35, 66, 32)

                        index.setBackgroundColor(color)
                        src.setBackgroundColor(color)
                        dest.setBackgroundColor(color)
                        proto.setBackgroundColor(color)
                        info.setBackgroundColor(color)

                        table.insertRow(l)
                        table.setItem(l, 0, index)
                        table.setItem(l, 1, src)
                        table.setItem(l, 2, dest)
                        table.setItem(l, 3, proto)
                        table.setItem(l, 4, info)
                        l += 1

                a = not a
                if tcp_flags[0] == " SYN" and tcp_flags[1] == " SYN ACK":

                    if tcp_flags[len(tcp_flags)-1] == " RST ACK":
                        color = QColor('GREEN')
                    elif "FIN" in tcp_flags[len(tcp_flags)-4] and tcp_flags[len(tcp_flags)-3] == " ACK" and "FIN" in tcp_flags[len(tcp_flags)-2] and tcp_flags[len(tcp_flags)-1] == " ACK":
                        color = QColor('GREEN')
                    elif "FIN" in tcp_flags[len(tcp_flags)-3] and "FIN" in tcp_flags[len(tcp_flags)-2] and tcp_flags[len(tcp_flags)-1] == " ACK":
                        color = QColor('GREEN')
                    elif "FIN" in tcp_flags[len(tcp_flags)-4] and "FIN" in tcp_flags[len(tcp_flags)-3] and "ACK" in tcp_flags[len(tcp_flags)-2] and "ACK" in tcp_flags[len(tcp_flags)-1]:
                        color = QColor('GREEN')
                else:
                    color = QColor('RED')
                index.setBackgroundColor(color)
                src.setBackgroundColor(color)
                dest.setBackgroundColor(color)
                proto.setBackgroundColor(color)
                info.setBackgroundColor(color)

    def filter_tftp(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)

        k = 0
        a = True
        for packet in self.packets:
            if packet.source_port == 69 or packet.dest_port == 69:
                a = not a
            if packet.l4_type == "tftp":
                infor = str(packet.source_port) + " -> " + str(packet.dest_port)

                table.insertRow(k)
                index = QTableWidgetItem(str(self.packets.index(packet) + 1))
                src = QTableWidgetItem(packet.get_source_address())
                dest = QTableWidgetItem(packet.get_dest_address())
                proto = QTableWidgetItem(packet.get_protocol())
                info = QTableWidgetItem(infor)

                if a:
                    color = QColor(69, 34, 34)
                else:
                    color = QColor(35, 66, 32)

                index.setBackgroundColor(color)
                src.setBackgroundColor(color)
                dest.setBackgroundColor(color)
                proto.setBackgroundColor(color)
                info.setBackgroundColor(color)
                table.setItem(k, 0, index)
                table.setItem(k, 1, src)
                table.setItem(k, 2, dest)
                table.setItem(k, 3, proto)
                table.setItem(k, 4, info)
                k += 1



    def filter_arp(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)
        arps = []
        added = []
        k = 0

        for packet in self.packets:
            if packet.l2_type == "ARP":
                arps.append(packet)
        a = True
        for i in range(len(arps)):
            if arps[i] not in added:
                for j in range(len(arps)):
                    if arps[j] not in added and arps[i].arp_dst_ip == arps[j].arp_dst_ip and arps[i].arp_src_ip == arps[j].arp_src_ip:
                        arp = "[" + arps[j].arp_op + "] "
                        if arps[j].arp_op == "Request":
                            arp += "Who has " + arps[j].arp_dst_ip + "? Tell " + arps[j].arp_src_ip
                        elif arps[j].arp_op == "Reply":
                            arp += arps[j].arp_src_ip + " is at " + arps[j].arp_src_mac
                        table.insertRow(k)
                        index = QTableWidgetItem(str(self.packets.index(arps[j])+1))
                        src = QTableWidgetItem(arps[j].get_source_address())
                        dest = QTableWidgetItem(arps[j].get_dest_address())
                        proto = QTableWidgetItem(arps[j].get_protocol())
                        info = QTableWidgetItem(arp)

                        if a:
                            color = QColor(69, 34, 34)
                        else:
                            color = QColor(35, 66, 32)

                        index.setBackgroundColor(color)
                        src.setBackgroundColor(color)
                        dest.setBackgroundColor(color)
                        proto.setBackgroundColor(color)
                        info.setBackgroundColor(color)

                        table.setItem(k, 0, index)
                        table.setItem(k, 1, src)
                        table.setItem(k, 2, dest)
                        table.setItem(k, 3, proto)
                        table.setItem(k, 4, info)
                        k += 1
                        added.append(arps[j])
                for j in range(len(arps)):
                    if arps[j] not in added and arps[i].arp_dst_ip == arps[j].arp_src_ip and arps[i].arp_src_ip == arps[j].arp_dst_ip:
                        arp = "[" + arps[j].arp_op + "] "
                        if arps[j].arp_op == "Request":
                            arp += "Who has " + arps[j].arp_dst_ip + "? Tell " + arps[j].arp_src_ip
                        elif arps[j].arp_op == "Reply":
                            arp += arps[j].arp_src_ip + " is at " + arps[j].arp_src_mac

                        index = QTableWidgetItem(str(self.packets.index(arps[j])+1))
                        src = QTableWidgetItem(arps[j].get_source_address())
                        dest = QTableWidgetItem(arps[j].get_dest_address())
                        proto = QTableWidgetItem(arps[j].get_protocol())
                        info = QTableWidgetItem(arp)
                        if a:
                            color = QColor(69, 34, 34)
                        else:
                            color = QColor(35, 66, 32)

                        index.setBackgroundColor(color)
                        src.setBackgroundColor(color)
                        dest.setBackgroundColor(color)
                        proto.setBackgroundColor(color)
                        info.setBackgroundColor(color)

                        table.insertRow(k)
                        table.setItem(k, 0, index)
                        table.setItem(k, 1, src)
                        table.setItem(k, 2, dest)
                        table.setItem(k, 3, proto)
                        table.setItem(k, 4, info)
                        k += 1
                        added.append(arps[j])
                        break
                a = not a

    def populate(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)
        i = 0
        tftp = False
        for packet in self.packets:
            table.insertRow(i)
            protocol = packet.get_protocol()
            if protocol == "UDP" and packet.l4_type == "" and tftp == True:
                protocol = "tftp"
                packet.l4_type = "tftp"
            table.setItem(i, 0, QTableWidgetItem(str(i+1)))
            table.setItem(i, 1, QTableWidgetItem(packet.get_source_address()))
            table.setItem(i, 2, QTableWidgetItem(packet.get_dest_address()))
            table.setItem(i, 3, QTableWidgetItem(protocol))
            if packet.source_port != 0:
                ports = str(packet.source_port) + " -> " + str(packet.dest_port)
                if packet.tcp_flag != "":
                    ports += " [" + packet.tcp_flag + "]"
                if packet.get_protocol() == "TCP":
                    tcp_info = packet.tcp_parse()
                    ports += " Seq=" + str(tcp_info["seq"])
                    if "ack" in tcp_info.keys():
                        ports += " Ack=" + str(tcp_info["ack"])
                    ports += " Win=" + str(tcp_info["win"])
                table.setItem(i, 4, QTableWidgetItem(ports))
            if packet.arp_op != "":
                arp = "[" + packet.arp_op + "] "
                if packet.arp_op == "Request":
                    arp += "Who has " + packet.arp_dst_ip + "? Tell " + packet.arp_src_ip
                elif packet.arp_op == "Reply":
                    arp += packet.arp_src_ip + " is at " + packet.arp_src_mac
                table.setItem(i, 4, QTableWidgetItem(arp))
            if packet.l3_type == "ICMP":
                icmp = packet.icmp_type
                table.setItem(i, 4, QTableWidgetItem(icmp))
            if tftp == True and (packet.l3_type != "UDP" or (packet.l3_type == "UDP" and packet.l4_type != "tftp")):
                tftp = False
            if packet.l4_type == "tftp" and (packet.tftp_type == 1 or packet.tftp_type == 2):
                tftp = True
            i += 1


