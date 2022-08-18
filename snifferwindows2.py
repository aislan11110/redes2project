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
    ipselecionado=selecioneoip()
    x=0
    while x!=-1:
        raw_data = rip.recvfrom(65535)
        raw_data2 = raw_data[0]
        #cabeçalho Ethernet
        #destino_mac, source_mac, protocolo_eth, eth_length = frame_ethernet(raw_data2)
        #print abaixo
        #print('destino_mac: {}, fonte_mac: {}, protocolo: {}'.format(destino_mac,source_mac,protocolo_eth))
        protocolo_eth =8
        eth_length=0
        if protocolo_eth== 8 :
            #cabeçalho ip
            (versão,iph_tamanho,ttl,protocolo,source_addr,destination_addr)\
                = ipv4(raw_data2[:20])
            restodosdados= raw_data2[20:]
            if(ipselecionado!='' and ipselecionado== source_addr or ipselecionado == destination_addr):
            #print abaixo
                print("IPV4:")
                print("versão:{}, tamanho do cabeçalho IP: {}, tempo de vida: {}, protocolo: {},"
                  "endereço fonte: {}, endereço destino: {}".format(
                  versão,iph_tamanho,ttl,protocolo,source_addr,destination_addr))
                printprotocolo(restodosdados,protocolo)
            elif ipselecionado=='':
                print("IPV4:")
                print("versão:{}, tamanho do cabeçalho IP: {}, tempo de vida: {}, protocolo: {},"
                      "endereço fonte: {}, endereço destino: {}".format(
                    versão, iph_tamanho, ttl, protocolo, source_addr, destination_addr))
                printprotocolo(restodosdados,protocolo)
        x=x+1

    print()

def printprotocolo(restodosdados,protocolo):
    # print abaixo
    # Pacote TCP
    if protocolo == 6:
        (porta_fonte, porta_destino, sequencia, reconhecimento, tcph_tamanho) \
            = protocolo_TCP(restodosdados[:20])
        data = restodosdados[20:]
        # print abaixo
        print("Pacote TCP:")
        print(
            "Porta fonte: {}, Porta destino: {}, Sequencia numerica: {}, reconhecimento: {}, Offset: {}".format(
                porta_fonte, porta_destino, sequencia, reconhecimento, tcph_tamanho))
        print()
        print(data)


    # Pacote ICMP
    elif protocolo == 1:
        (icmp_tipo, codigo, checksum) \
            = protocolo_ICMP(restodosdados[:4])
        data = restodosdados[4:]
        # print abaixo
        print("Pacote ICMP:")
        print("Tipo: {}, codigo: {}, checksum: {}".format(icmp_tipo, codigo, checksum))
        print()
        print(data)

    # Pacote UDP
    elif protocolo == 17:
        (porta_fonte, porta_destino, udp_tamanho, checksum) \
            = protocolo_UDP(restodosdados[:8])
        data = restodosdados[8:]
        # print abaixo
        print("Pacote UDP:")
        print("Porta fonte: {}, porta destino: {}, tamanho: {}, checksum: {}".format(
            porta_fonte, porta_destino, udp_tamanho, checksum))
        print()
        print(data)
    # Pacote IGMP
    elif protocolo == 2:
        (tipo, maxresptime, checksum) = protocolo_IGMP(restodosdados[:4])
        data = restodosdados[4:]
        print("Pacote IGMP:")
        print("Tipo: {}, tempo de resposta maximo: {}, checksum: {}"
              .format(tipo, maxresptime, checksum))
        print()
        print(data)
    # Pacote SCTP
    elif protocolo == 132:
        (porta_fonte, porta_destino, tag, checksum) = protocolo_SCTP(restodosdados[:12])
        data = restodosdados[12:]
        print("Pacote SCTP:")
        print("porta fonte: {}, porta destino: {}, tag de verificação: {}, checksum: {}"
              .format(porta_fonte, porta_destino, tag, checksum))
        print()
        print(data)

    else:
        print("protocolo diferente de TCP/UDP/ICMP/SCTP/IGMP")



def protocolo_TCP(data):
    tcph = struct.unpack('!HHLLBBHHH', data)

    porta_fonte = tcph[0]
    porta_destino = tcph[1]
    sequencia = tcph[2]
    reconhecimento = tcph[3]
    offset_reservado = tcph[4]
    tcph_tamanho = offset_reservado >> 4
    return porta_fonte,porta_destino,sequencia,reconhecimento, tcph_tamanho   #tcph_tamanho= offset errei!

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

def protocolo_IGMP(data):
     igmph = struct.unpack('!BBH', data)

     igmp_tipo = igmph[0]
     igmp_maxresptime = igmph[1]
     checksum = igmph[2]
     return igmp_tipo,igmp_maxresptime,checksum

def protocolo_SCTP(data):
    sctph = struct.unpack('HHLL',data)

    porta_fonte =sctph[0]
    porta_destino = sctph[1]
    tag_verificação = sctph[2]
    checksum = sctph[3]
    return porta_fonte, porta_destino, tag_verificação, checksum

def ipv4(data):
    iph= struct.unpack('!BBHHHBBH4s4s', data)
    versão_ihl = iph[0]
    versão = versão_ihl >> 4
    ihl = versão_ihl & 0xF
    iph_lenght = ihl * 4
    if(ihl!=5):
      print("tamanho variado do ipv4 header?")

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

def selecioneoip():
    while True:
     ipselecionado = input('digite um ip:')
     if ipselecionado=='' :
         return ''
     elif(ipverified(ipselecionado)==False):
         ipselecionado = input('digite um ip:')
     else:
         return ipselecionado


def ipverified(ip):
    strsplitada = ip.split('.')
    if(len(strsplitada)!=4):
        return False
    else:
        for item in strsplitada:
            if (int(item)>=0) and (int(item)<=255) :
                continue
            else:
                return False
        return True


def formatomultilinha(prefix,string, size=80):
    size -= len(prefix)
    if(isinstance(string,bytes)):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()
