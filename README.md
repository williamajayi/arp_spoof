# ARP Spoof

Simple program to poison an ARP table by sending spoofed packets to a target on the network

Requirements:

[+]  Python 3.0 and above

[+]  Scapy 2.2 and above (pip install scapy)

Usage:

python arp_spoof.py -i [interface] -t [Destination IP Address] -s [Spoof IP Address]

python3 arp_spoof.py -i [interface] -t [Destination IP Address] -s [Spoof IP Address]

Program automatically runs shell command to enable/disable IP forwarding using the following commands: 

echo 1 > /proc/sys/net/ipv4/ip_forward

echo 0 > /proc/sys/net/ipv4/ip_forward
