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

    def filter_arp(self, table):
        #while table.rowCount() > 0:
        #    table.removeRow(0)
        table.setRowCount(0)
        present = []
        k = 0
        for i in range(len(self.packets)):
            if self.packets[i].l2_type == "ARP" and self.packets[i] not in present:
                table.insertRow(k)
                table.setItem(k, 0, QTableWidgetItem(str(i)))
                table.setItem(k, 1, QTableWidgetItem(self.packets[i].get_source_address()))
                table.setItem(k, 2, QTableWidgetItem(self.packets[i].get_dest_address()))
                table.setItem(k, 3, QTableWidgetItem(self.packets[i].get_protocol()))
                arp = "[" + self.packets[i].arp_op + "] "
                if self.packets[i].arp_op == "Request":
                    arp += "Who has " + self.packets[i].arp_dst_ip + "? Tell " + self.packets[i].arp_src_ip
                elif self.packets[i].arp_op == "Reply":
                    arp += self.packets[i].arp_src_ip + " is at " + self.packets[i].arp_src_mac
                table.setItem(k, 4, QTableWidgetItem(arp))
                k += 1
                present.append(self.packets[i])

                for l in range(i, len(self.packets)):
                    if self.packets[l] not in present:
                        if self.packets[l].l2_type == "ARP" and self.packets[l].arp_dst_ip == self.packets[i].arp_src_ip and self.packets[l].arp_src_ip == self.packets[i].arp_dst_ip:
                            present.append(self.packets[l])
                            table.insertRow(k)
                            table.setItem(k, 0, QTableWidgetItem(str(l)))
                            table.setItem(k, 1, QTableWidgetItem(self.packets[l].get_source_address()))
                            table.setItem(k, 2, QTableWidgetItem(self.packets[l].get_dest_address()))
                            table.setItem(k, 3, QTableWidgetItem(self.packets[l].get_protocol()))
                            arp = "[" + self.packets[l].arp_op + "] "
                            if self.packets[l].arp_op == "Request":
                                arp += "Who has " + self.packets[l].arp_dst_ip + "? Tell " + self.packets[l].arp_src_ip
                            elif self.packets[l].arp_op == "Reply":
                                arp += self.packets[l].arp_src_ip + " is at " + self.packets[l].arp_src_mac
                            table.setItem(k, 4, QTableWidgetItem(arp))
                            k += 1
                            break
    def populate(self, table):
        while table.rowCount() > 0:
            table.removeRow(0)
        table.setRowCount(0)
        i = 0

        for packet in self.packets:
            table.insertRow(i)
            table.setItem(i, 0, QTableWidgetItem(str(i)))
            table.setItem(i, 1, QTableWidgetItem(packet.get_source_address()))
            table.setItem(i, 2, QTableWidgetItem(packet.get_dest_address()))
            table.setItem(i, 3, QTableWidgetItem(packet.get_protocol()))
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
            i += 1


