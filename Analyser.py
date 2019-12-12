from PySide2.QtGui import QColor, QBrush
from PySide2.QtWidgets import QTableWidgetItem

from Packet import Packet
import operator

class Analyser:
    ips = {}
    packets = []
    text_color = QColor(242, 242, 242)
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
        most_active = 0
        most_active_ip = ""
        for i in self.ips.keys():
            if self.ips[i] > most_active:
                most_active = self.ips[i]
                most_active_ip = i
        content += most_active_ip + " - " +str(most_active)
        return content

    def get_hex(self, mac, l1, l2, l3, l4, IP, ports):
        content = ""
        counter = 0

        for packet in self.packets:
            my_packet = packet
            a = len(packet.data)
            counter += 1
            content += "ramec " + str(counter) + "\n"
            content += "dĺžka rámca z poskytnutá pcap API - " + str(a) + " B\n"
            content += "dĺžka rámca prenášaného po médiu  - "
            if (a < 60):
                content += str(64) + " B"
            else:
                content += str(a + 4) + " B"
            content += "\n"

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

            content += str(my_packet.get_contents_hex().decode())[0:len(my_packet.get_contents_hex())] + "\n\n"

        content += "IP's:\n"
        for a in self.ips:
            content += a + "\n"
        content += "Most active sender: " + max(self.ips.items(), key=operator.itemgetter(1))[0] + "\n"

        return content

    def filter_icmp(self, table, rm):
        if rm:
            while table.rowCount() > 0:
                table.removeRow(0)
            table.setRowCount(0)
            l = 0
        else:
            l = table.rowCount()

        icmp_packets = []
        for packet in self.packets:
            if packet.l3_type == "ICMP":
                icmp_packets.append(packet)
        a = True
        inserted = []
        for k in range(len(icmp_packets)):
            if icmp_packets[k] not in inserted:
                a = not a
                if icmp_packets[k].icmp_type == "TTL Exceeded":
                    msg = "TTL Exceeded"
                    self.insert_packet(table, icmp_packets[k], l, 3, msg)
                else:
                    msg = icmp_packets[k].icmp_type + " Id: " + str(icmp_packets[k].icmp_id) + " Seq: " + str(icmp_packets[k].icmp_seq)
                    self.insert_packet(table, icmp_packets[k], l, a, msg)
                inserted.append(icmp_packets[k])
                l += 1
            if icmp_packets[k].icmp_type == "Echo Request":
                for j in range(k+1, len(icmp_packets)):
                    if icmp_packets[j] not in inserted and icmp_packets[j].icmp_type == "Echo Reply":
                        if icmp_packets[j].icmp_id == icmp_packets[k].icmp_id and icmp_packets[j].icmp_seq == icmp_packets[k].icmp_seq:
                            msg = icmp_packets[j].icmp_type + " Id: " + str(icmp_packets[j].icmp_id) + " Seq: " + str(
                                icmp_packets[j].icmp_seq)
                            self.insert_packet(table, icmp_packets[j], l, a, msg)
                            inserted.append(icmp_packets[j])
                            l += 1
                            break

    def filter_tcp(self, table, rm):
        if rm:
            while table.rowCount() > 0:
                table.removeRow(0)
            table.setRowCount(0)
            l = 0
        else:
            l = table.rowCount()
        tcp_packets = []
        done = []

        for packet in self.packets:
            if packet.l3_type == "TCP":
                tcp_packets.append(packet)
        a = True
        for j in range(len(tcp_packets)):
            if (tcp_packets[j] not in done):
                tcp_flags = []
                for k in range(j, len(tcp_packets)):

                    if ((tcp_packets[j].source_port == tcp_packets[k].source_port and tcp_packets[j].dest_port == tcp_packets[k].dest_port and tcp_packets[k].source_ip==tcp_packets[j].source_ip and tcp_packets[k].dest_ip == tcp_packets[j].dest_ip) or (tcp_packets[j].source_port == tcp_packets[k].dest_port and tcp_packets[j].dest_port == tcp_packets[k].source_port and tcp_packets[k].source_ip==tcp_packets[j].dest_ip and tcp_packets[k].dest_ip == tcp_packets[j].source_ip)):

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
                        index.setForeground(QBrush(self.text_color))
                        src.setForeground(QBrush(self.text_color))
                        dest.setForeground(QBrush(self.text_color))
                        proto.setForeground(QBrush(self.text_color))
                        info.setForeground(QBrush(self.text_color))

                        table.insertRow(l)
                        table.setItem(l, 0, index)
                        table.setItem(l, 1, src)
                        table.setItem(l, 2, dest)
                        table.setItem(l, 3, proto)
                        table.setItem(l, 4, info)
                        l += 1

                a = not a
                if len(tcp_flags) >= 2 and tcp_flags[0] == " SYN" and tcp_flags[1] == " SYN ACK":

                    if "RST" in tcp_flags[len(tcp_flags)-1]:
                        color = QColor('GREEN')
                    elif "FIN" in tcp_flags[len(tcp_flags)-4] and tcp_flags[len(tcp_flags)-3] == " ACK" and "FIN" in tcp_flags[len(tcp_flags)-2] and tcp_flags[len(tcp_flags)-1] == " ACK":
                        color = QColor('GREEN')
                    elif "FIN" in tcp_flags[len(tcp_flags)-3] and "FIN" in tcp_flags[len(tcp_flags)-2] and tcp_flags[len(tcp_flags)-1] == " ACK":
                        color = QColor('GREEN')
                    elif "FIN" in tcp_flags[len(tcp_flags)-4] and "FIN" in tcp_flags[len(tcp_flags)-3] and "ACK" in tcp_flags[len(tcp_flags)-2] and "ACK" in tcp_flags[len(tcp_flags)-1]:
                        color = QColor('GREEN')
                    else:
                        color = QColor('RED')
                else:
                    color = QColor('RED')

                index.setBackgroundColor(color)
                src.setBackgroundColor(color)
                dest.setBackgroundColor(color)
                proto.setBackgroundColor(color)
                info.setBackgroundColor(color)

    def sort_communicastions(self, table):
        self.filter_arp(table, True)
        self.filter_icmp(table, False)
        self.filter_tcp(table, False)
        self.filter_tftp(table, False)

        for packet in self.packets:
            if packet.l2_type != "ARP" and packet.l3_type != "ICMP" and packet.l3_type != "TCP" and packet.l4_type != "tftp":
                table.insertRow(table.rowCount())
                table.setItem(table.rowCount()-1, 0, QTableWidgetItem(str(table.rowCount())))
                table.setItem(table.rowCount()-1, 1, QTableWidgetItem(packet.get_source_address()))
                table.setItem(table.rowCount()-1, 2, QTableWidgetItem(packet.get_dest_address()))
                table.setItem(table.rowCount()-1, 3, QTableWidgetItem(packet.get_protocol()))
                ports = ""
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
                table.setItem(table.rowCount()-1, 4, QTableWidgetItem(ports))


    def insert_packet(self, table, packet, k, a, infor):

        table.insertRow(k)
        index = QTableWidgetItem(str(self.packets.index(packet) + 1))
        src = QTableWidgetItem(packet.get_source_address())
        dest = QTableWidgetItem(packet.get_dest_address())
        proto = QTableWidgetItem(packet.get_protocol())
        info = QTableWidgetItem(infor)
        if int(a) != -1:
            if int(a) == 1:
                color = QColor(69, 34, 34)
            elif int(a) == 0:
                color = QColor(35, 66, 32)
            elif int(a) == 3:
                color = QColor(0, 0, 0)

            index.setBackgroundColor(color)
            src.setBackgroundColor(color)
            dest.setBackgroundColor(color)
            proto.setBackgroundColor(color)
            info.setBackgroundColor(color)
            index.setForeground(QBrush(self.text_color))
            src.setForeground(QBrush(self.text_color))
            dest.setForeground(QBrush(self.text_color))
            proto.setForeground(QBrush(self.text_color))
            info.setForeground(QBrush(self.text_color))
        table.setItem(k, 0, index)
        table.setItem(k, 1, src)
        table.setItem(k, 2, dest)
        table.setItem(k, 3, proto)
        table.setItem(k, 4, info)

    def filter_http(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)
        k = 0
        for packet in self.packets:
            if packet.get_protocol() == "http":
                self.insert_packet(table, packet, k, -1, "")
                k += 1

    def filter_https(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)
        k = 0
        for packet in self.packets:
            if packet.get_protocol() == "https":
                self.insert_packet(table, packet, k, -1, "")
                k += 1

    def filter_telnet(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)
        k = 0
        for packet in self.packets:
            if packet.get_protocol() == "telnet":
                self.insert_packet(table, packet, k, -1, "")
                k += 1


    def filter_tftp(self, table, rm):
        if rm:
            while table.rowCount() > 0:
                table.removeRow(0)
            table.setRowCount(0)
            k = 0
        else:
            k = table.rowCount()

        a = True
        added_ports = []
        for packet in self.packets:
            if packet.source_port == 69 or packet.dest_port == 69:
                a = not a
            if packet.l4_type == "tftp" and packet.source_port not in added_ports:
                src_port = packet.source_port
                added_ports.append(src_port)
                dst_port = -1
                infor = str(packet.source_port) + " -> " + str(packet.dest_port)
                self.insert_packet(table, packet, k, a, infor)
                k += 1
                for i in range(self.packets.index(packet), len(self.packets)):
                    if dst_port == -1 and self.packets[i].dest_port == src_port:
                        dst_port = self.packets[i].source_port
                        added_ports.append(dst_port)
                        infor = str(self.packets[i].source_port) + " -> " + str(self.packets[i].dest_port)
                        self.insert_packet(table, self.packets[i], k, a, infor)
                        k += 1
                    elif self.packets[i].source_port == src_port and self.packets[i].dest_port == dst_port:
                        infor = str(self.packets[i].source_port) + " -> " + str(self.packets[i].dest_port)
                        self.insert_packet(table, self.packets[i], k, a, infor)
                        k += 1
                    elif self.packets[i].source_port == dst_port and self.packets[i].dest_port == src_port:
                        infor = str(self.packets[i].source_port) + " -> " + str(self.packets[i].dest_port)
                        self.insert_packet(table, self.packets[i], k, a, infor)
                        k += 1



    def filter_arp(self, table, rm):
        if rm:
            while table.rowCount() > 0:
                table.removeRow(0)
            table.setRowCount(0)
            k = 0
        else:
            k = table.rowCount()
        arps = []
        added = []

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
                        index.setForeground(QBrush(self.text_color))
                        src.setForeground(QBrush(self.text_color))
                        dest.setForeground(QBrush(self.text_color))
                        proto.setForeground(QBrush(self.text_color))
                        info.setForeground(QBrush(self.text_color))

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
                        index.setForeground(QBrush(self.text_color))
                        src.setForeground(QBrush(self.text_color))
                        dest.setForeground(QBrush(self.text_color))
                        proto.setForeground(QBrush(self.text_color))
                        info.setForeground(QBrush(self.text_color))

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
        added_ports = []
        for packet in self.packets:
            table.insertRow(i)
            protocol = packet.get_protocol()
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
            if packet.l4_type == "tftp" and packet.source_port not in added_ports:
                src_port = packet.source_port
                added_ports.append(src_port)
                dst_port = -1
                for j in range(self.packets.index(packet), len(self.packets)):
                    if dst_port == -1 and self.packets[j].dest_port == src_port:
                        dst_port = self.packets[j].source_port
                        added_ports.append(dst_port)
                        self.packets[j].l4_type = "tftp"
                    elif self.packets[j].source_port == src_port and self.packets[j].dest_port == dst_port:
                        self.packets[j].l4_type = "tftp"
                    elif self.packets[j].source_port == dst_port and self.packets[j].dest_port == src_port:
                        self.packets[j].l4_type = "tftp"

            i += 1


