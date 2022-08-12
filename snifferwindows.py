import socket
import struct
import textwrap

TAB_1 = '\t -  '
TAB_2 = '\t\t -  '
TAB_3 = '\t\t\t -  '
TAB_4 = '\t\t\t\t -  '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    '192.168.1.1'
    host =socket.gethostbyname(socket.gethostname())
    rip = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
    rip.bind((host,0))
    rip.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    rip.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    while True:
        raw_data, addr =  rip.recvfrom(65565)
        dest_mac, rem_mac, tipproto, data = frame_ethernet(raw_data)
        print('\n Ethernet Frame:')
        print('Destinação: {}, fonte: {}, Protocolo: {}'.format(dest_mac, rem_mac, tipproto))

        if tipproto==8:
            (versão, cabeçalho_tamanho, tempoparaviver, protocolo,fonte,alvo,data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 pacote:')
            print(TAB_2 + 'Versão: {}, tamanho do cabeçalho: {}, tempo de vida: {}'.format(versão,cabeçalho_tamanho,tempoparaviver))
            print(TAB_2 + 'Protocolo: {}, fonte: {}, alvo: {}'.format(protocolo,fonte,alvo))

            #icmp
            if protocolo == 1:
                icmp_tipo, codigo, checksum, data = icmp_pacote(data)
                print(TAB_1 + 'Pacote ICMP:')
                print(TAB_2 + 'Tipo: {}, codigo: {}, checksum: {}'.format(icmp_tipo,codigo,checksum))
                print(TAB_2 + 'data:')
                print(formatomultilinha(DATA_TAB_3,data))
            #TCP
            elif protocolo == 6:
                (porta_fonte, destinação, sequencia, reconhecimento, \
                flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,data) = tcp_pacote(data)
                print(TAB_1 +'TCP segmento:')
                print(TAB_2 + 'Porta fonte: {}, Porta de destino: {}'.format(porta_fonte,destinação))
                print(TAB_2 + 'Sequencia: {}, reconhecimento: {}'.format(sequencia,reconhecimento))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                    flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin
                ))
                print(TAB_2 + 'Data:')
                print(formatomultilinha(DATA_TAB_3,data))

            #UDP
            elif protocolo == 17:
                (porta_fonte, porta_destino, tamanho, data) = udp_pacote(data)
                print(TAB_1 + 'UDP segmento:')
                print(TAB_2 + 'porta fonte: {}, porta destino: {}, tamanho: {}'
                      .format(porta_fonte,porta_destino, tamanho))

            else:
                print(TAB_1 + 'Data:')
                print(formatomultilinha(DATA_TAB_2,data))
        else :
            print('Data:')
            print(formatomultilinha(DATA_TAB_1,data))





def frame_ethernet(data):
    ip_header = data[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s',ip_header)
    versão_ihl = iph[0]
    versão = versão_ihl >> 4

    s_addr = iph[8]
    d_addr = iph[9]
    destinação_mac, remetente_mac, tipoprotocolo = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(destinação_mac), get_mac_addr(remetente_mac), socket.htons(tipoprotocolo),data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def ipv4_packet(data):
    versão_cabeçalho_tamanho=data[0]
    versão = versão_cabeçalho_tamanho >> 4
    cabeçalho_tamanho =  (versão_cabeçalho_tamanho & 15)*4
    tempoparaviver , protocolo, fonte, alvo = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return versão, cabeçalho_tamanho, tempoparaviver , protocolo , ipv4(fonte) , ipv4(alvo), data[cabeçalho_tamanho:]

def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_pacote(data):
    icmp_tipo, codigo, checksum = struct.unpack('! B B H', data[:4])
    return icmp_tipo, codigo , checksum, data[4:]

def udp_pacote(data):
    porta_fonte, porta_dest,tamanho = struct.unpack('! H H 2x H', data[:8])
    return porta_fonte,porta_dest,tamanho,data[8:]

def tcp_pacote(data):
    (porta_fonte, destinação,sequencia,reconhecimento, offset_reversed_flag)\
        = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reversed_flag >> 12)*4
    flag_urg = (offset_reversed_flag & 32) >> 5
    flag_ack = (offset_reversed_flag & 16) >> 4
    flag_psh = (offset_reversed_flag & 8) >> 3
    flag_rst = (offset_reversed_flag & 4) >> 2
    flag_syn = (offset_reversed_flag & 2) >> 1
    flag_fin = offset_reversed_flag & 1
    return porta_fonte, destinação, sequencia, reconhecimento,\
           flag_urg, flag_ack,flag_psh,flag_rst,flag_syn, flag_fin,data[offset:]

def formatomultilinha(prefix,string, size=80):
    size -= len(prefix)
    if(isinstance(string,bytes)):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()
