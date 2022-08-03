import socket
import struct
import textwrap

def main():
    '192.168.1.1'
    host =socket.gethostbyname(socket.gethostname())
    rip = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    rip.bind((host,0))
    rip.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    rip.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    while True:
        raw_data, addr =  rip.recvfrom(65565)
        dest_mac, rem_mac, tipproto, data = frame_ethernet(raw_data)
        print('\n Ethernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, rem_mac, tipproto))


def frame_ethernet(data):
    destinação_mac, remetente_mac, tipoprotocolo = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(destinação_mac), get_mac_addr(remetente_mac), socket.htons(tipoprotocolo),data[:14]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

if __name__ == '__main__':
    main()
