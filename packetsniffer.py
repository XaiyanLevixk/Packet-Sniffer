from email.base64mime import header_length
import socket
import struct
import textwrap
from typing import Protocol

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source {}, protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print("IPv4 Packet: ")
            print("version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print("protocol: {}, source: {}, destnation: {}".format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print("ICMP Packet: ")
                print("Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                print("Data: ")
                print(data)

            elif proto == 6:
                (src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print("TCP Segment:")
                print("source port: {}, destination port: {}".format(src_port, dest_port))
                print("sequence: {}, Ack: {}".format(sequence, ack))
                print("Flags:")
                print("URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print("Data:")
                print(data)

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print("UDP Segment")
                print("source port: {}, destination port: {}, length: {}".format(src_port, dest_port, length))
                print("data:")
                print(data)

            else:
                print("data:")
                print(data)
        
        else:
            print("data:")
            print(data)

# unpack ethernet frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return properly formatted mac address

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


#unpack IPV4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length>>4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(dest), data[header_length:]


#returns formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


# unpacks icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpacks tcp segment
def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_reserves_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserves_flags>>12) * 4
    flag_urg = (offset_reserves_flags & 32)>>5
    flag_ack = (offset_reserves_flags & 16)>>4
    flag_psh = (offset_reserves_flags & 8)>>3
    flag_rst = (offset_reserves_flags & 4)>>2
    flag_syn = (offset_reserves_flags & 2)>>1
    flag_fin = (offset_reserves_flags & 1)
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
    

main()

