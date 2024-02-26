from scapy.all import *
import getopt
from datetime import datetime


def detectInjection(pkt):

    if UDP in pkt:
        if pkt[UDP].sport != 53:  # We are interested only in DNS responses
            return
    if TCP in pkt:
        if pkt[TCP].sport != 53:
            return

    key = pkt[DNS].qd.qname.decode("utf-8")[:-1] + ",{},{}".format(pkt[DNS].id, pkt[DNSRR].type)  # We generate the dictionary key
    if key in queries.keys():  # We already received a packet with the same key, so we record the attack
        date = datetime.now()
        log.write(date.strftime("%B %d %Y %H:%M:%S") + "\n")
        log.write("TXID {} Request ".format(hex(pkt[DNS].id)) + pkt[DNS].qd.qname.decode("utf-8")[:-1] + "\n")
        log.write("Answer1 ")
        for val in queries[key]:
            log.write(val + " ")
        log.write("\n")
        log.write("Answer2 ")
        for i in range(pkt[DNS].ancount):
            log.write(pkt[DNS].an[i].rdata + " ")
        log.write("\n\n")
    else:
        ip = []
        for i in range(pkt[DNS].ancount):  # We store all the IPs of the response
            ip.append(pkt[DNS].an[i].rdata)
        queries[key] = ip  # We save the response in the dictionary


queries = {}  # Dictionary
log = open("attack_log.txt", "w")

interface = "en0"  # Default interface

standard = True  # To understand the type of analysis (on file or live)

opts, args = getopt.getopt(sys.argv[1:], "i:r:")
for opt, arg in opts:
    if opt == "-i":
        interface = arg
    if opt == '-r':
        standard = False
        file = arg

if standard:
    sniff(iface=interface, filter="port 53", prn=detectInjection)
else:
    sniff(offline=file, filter="port 53", prn=detectInjection)