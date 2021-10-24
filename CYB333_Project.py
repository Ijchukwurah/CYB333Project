
#python wasn't installed properly so I had to import in this way.
from scapy.all import *
from scapy.all import rdpcap
from scapy.all import hexdump


fname = input("Enter a pcap file: ")
#with open(secondscan.pcap, 'rb') as fname:
fpacket = rdpcap(fname)
pkt = fpacket
pkt_nmbr = len(pkt)
print("There are " , pkt_nmbr, " packets, but remember the count starts at '0'")
while True:
    try:
        q2 = int(input("If you have a specific packet you want to search, enter it now: "))
        pk0 = pkt[q2]
        pk1 = pk0['IP']
        print("Summary :", pk0.summary())
        print("Source IP ", pk1.src)
        print("Destination IP ", pk1.dst)
        print("Port number ", pk1.dport)
        print(hexdump(pk1))
    except:
        print("Packet out of range or not specified")


