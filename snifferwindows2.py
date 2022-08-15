import socket
import struct
import textwrap


def main():
    host = socket.gethostbyname(socket.gethostname())
    rip = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                        #socket.ntohs(0x0003)
                        socket.IPPROTO_IP
                        )
    rip.bind((host, 0))
    rip.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    rip.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    x=0
    while x!=10:
        raw_data = rip.recvfrom(65565)
        raw_data2 = raw_data[0]
        #cabeçalho Ethernet
       # destino_mac, source_mac, protocolo_eth, eth_length = frame_ethernet(raw_data2)
        #print abaixo
        #print('destino_mac: {}, fonte_mac: {}, protocolo: {}'.format(destino_mac,source_mac,protocolo_eth))
        protocolo_eth =8
        eth_length=0
        if protocolo_eth== 8 :
            #cabeçalho ip
            (versão,iph_tamanho,ttl,protocolo,source_addr,destination_addr)\
                = ipv4(raw_data2[:20])
            restodosdados= raw_data2[20:]
            #print abaixo
            print("IPV4:")
            print("versão:{}, tamanho do cabeçalho IP: {}, tempo de vida: {}, protocolo: {},"
                  "endereço fonte: {}, endereço destino: {}".format(
                  versão,iph_tamanho,ttl,protocolo,source_addr,destination_addr))

            #Pacote TCP
            if protocolo==6 :
                (porta_fonte,porta_destino,sequencia,reconhecimento,tcph_tamanho)\
                    =protocolo_TCP(restodosdados[:20])
                data = restodosdados[20:]
                #print abaixo
                print("Pacote TCP:")
                print("Porta fonte: {}, Porta destino: {}, Sequencia numerica: {}, reconhecimento: {}, Tamanho do cabeçalho TCP: {}".format(
                      porta_fonte,porta_destino,sequencia,reconhecimento,tcph_tamanho))
                print()
                print(data)


            #Pacote ICMP
            elif protocolo == 1 :
                (icmp_tipo,codigo,checksum)\
                    =protocolo_ICMP(restodosdados[:4])
                data = restodosdados[4:]
                #print abaixo
                print("Pacote ICMP:")
                print("Tipo: {}, codigo: {}, checksum: {}".format(icmp_tipo,codigo,checksum))
                print()
                print(data)

            #Pacote UDP
            elif protocolo == 17:
                (porta_fonte,porta_destino,udp_tamanho,checksum)\
                    =protocolo_UDP(restodosdados[:8])
                data = raw_data2[8:]
                #print abaixo
                print("Pacote UDP:")
                print("Porta fonte: {}, porta destino: {}, tamanho: {}, checksum: {}".format(
                      porta_fonte,porta_destino,udp_tamanho,checksum))
                print()
                print(data)
            else :
                print("protocolo diferente de TCP/UDP/ICMP")

        x=x+1

    print()




def protocolo_TCP(data):
    tcph = struct.unpack('!HHLLBBHHH', data)

    porta_fonte = tcph[0]
    porta_destino = tcph[1]
    sequencia = tcph[2]
    reconhecimento = tcph[3]
    offset_reservado = tcph[4]
    tcph_tamanho = offset_reservado >> 4
    return porta_fonte,porta_destino,sequencia,reconhecimento, tcph_tamanho

def protocolo_ICMP(data):
    icmph = struct.unpack('!BBH', data)
    icmp_tipo = icmph[0]
    codigo = icmph[1]
    checksum = icmph[2]
    return icmp_tipo,codigo,checksum

def protocolo_UDP(data):
    udph = struct.unpack('!HHHH', data)

    porta_fonte = udph[0]
    porta_destino = udph[1]
    tamanho = udph[2]
    checksum = udph[3]
    return porta_fonte,porta_destino,tamanho, checksum


def ipv4(data):
    iph= struct.unpack('!BBHHHBBH4s4s', data)
    versão_ihl = iph[0]
    versão = versão_ihl >> 4
    ihl = versão_ihl & 0xF
    iph_lenght = ihl * 4

    ttl = iph[5]
    protocolo = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    return versão,iph_lenght,ttl,protocolo,s_addr,d_addr

def frame_ethernet(data):
    eth_length = 14
    eth_header = data[:eth_length]
    eth = struct.unpack('! 6s 6s H', eth_header)
    protocolo_ethernet = socket.htons(eth[2])
    destino_mac = get_mac_addr(data[0:6])
    source_mac =  get_mac_addr(data[6:12])
    return destino_mac,source_mac,protocolo_ethernet, eth_length

def get_mac_addr(bytes_addr):
    bytes_str = map ('{:02x}'.format,bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

def formatomultilinha(prefix,string, size=80):
    size -= len(prefix)
    if(isinstance(string,bytes)):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()
