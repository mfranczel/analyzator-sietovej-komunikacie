
from Packet import Packet

class Analyser:
    def __init__(self, file_content):
        self.file_content = file_content

    def get_hex(self, mac, l1, l2, l3, l4, IP, ports):
        content = ""
        counter = 0

        for packet in self.file_content:
            my_packet = Packet(packet)
            a = len(packet)
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

            content += str(my_packet.get_contents_hex().decode())[0:len(my_packet.get_contents_hex())] + "\n"



        return content


