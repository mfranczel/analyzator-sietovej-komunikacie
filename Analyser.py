
from Packet import Packet

class Analyser:
    def __init__(self, file_content):
        self.file_content = file_content

    def get_hex(self):
        content = ""
        counter = 0

        for packet in self.file_content:
            my_packet = Packet(packet)
            counter += 1
            content += str(counter) + "\n"
            content += "Source MAC: " + my_packet.get_source_mac() + "\n"
            content += "Dest MAC: " + my_packet.get_dest_mac() + "\n"

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

            content += "L2: "
            content += my_packet.l2_type + "\n"
            content += str(my_packet.get_contents_hex().decode())[0:len(my_packet.get_contents_hex())] + "\n"

        return content


