"""
Find DNS records for a domain name or domain names for DNS record!

by Amitay Cahalon
"""

from sys import argv
from scapy.all import *

DEFAULT_GATEWAY = '8.8.8.8'
OPTS = ('-type=ptr', )
END_OF_PTR_QUERY= 'in-addr.arpa.'
PTR_TYPE = 12
DOT = '.'
MAX_TIMEOUT = 5


def is_valid_ipv4(ip_add: str) -> bool:
    """
    Gets a string and checks if it's a valid ipv4 address
    """
    splited_ip = ip_add.split(DOT)
    if len(splited_ip) == 4:
        valid_range = range(0, 256)
        for i in splited_ip:
            if not(i.isdigit() and int(i) in valid_range):
                return False
        return True
    return False


def is_valid_domain(domain: str) -> bool:
    """
    Gets a string and checks if it's a valid domain
    """
    splited_domain = domain.split(DOT)
    for letter in splited_domain[-1]:
        if not letter.islower():
            return False
    return True


def prints_ip(packet) -> None:
    """
    Gets a packet and prints all ip addresses it contains
    """
    print(f"Name:\n\t{argv[1]}\nAddresses:")
    for i in range(packet.ancount):
        print(f"\t{packet[DNS].an[i].rdata}")


def to_ptr(ip: str) -> str:
    """
    Convert an ip address to valid ptr query
    e.g. '1.2.3.4' -> '4.3.2.1.in-addr.arpa.'
    """
    valid_ptr = ''
    splitted_ip = ip.split(DOT)
    for i in range(3, -1, -1):
        valid_ptr += splitted_ip[i] + DOT
    valid_ptr += END_OF_PTR_QUERY
    return valid_ptr


def prints_hosts(packet) -> None:
    """
    Gets a packet and prints all hosts it contains
    """
    print(f"Address:\n\t{argv[2]}\nNames:")
    for i in range(packet.ancount):
        print(f"\t{packet[DNS].an[i].rdata.decode()}")


def handle_dns_query() -> None:
    """
    Builds a dns query packet, sends it and prints the appropriate response
    """
    query_pack = IP(dst=DEFAULT_GATEWAY) / UDP() / DNS(qd=DNSQR(qname=argv[1]))
    sniffed = sr1(query_pack, timeout=MAX_TIMEOUT, verbose=False)
    if not len(sniffed):
        print(f"Can't find '{argv[1]}': No response from server")
    else:
        prints_ip(sniffed)


def handle_reverse_mapping() -> None:
    """
    Builds a dns (ptr type) query packet, sends it and prints the appropriate response
    """
    pack = IP(dst=DEFAULT_GATEWAY) / UDP() / \
        DNS(qd=DNSQR(qname=to_ptr(argv[2]), qtype=PTR_TYPE))
    sniffed = sr1(pack, timeout=MAX_TIMEOUT, verbose=False)
    if not len(sniffed):
        print(f"Can't find '{argv[2]}': Non-existent domain")
    else:
        prints_hosts(sniffed)


def is_valid_reverse_request() -> bool:
    """
    Checks whether the user entered a valid dns (ptr type) query
    """
    return len(argv) == 3 and argv[1].lower() in OPTS and is_valid_ipv4(argv[2])


def is_valid_dns_request() -> bool:
    """
    Checks whether the user entered a valid dns query
    """
    return len(argv) == 2 and is_valid_domain(argv[1])


def main():
    # e.g. python nslookup.py -type=PTR 1.1.1.1
    if is_valid_reverse_request():
        handle_reverse_mapping()
    # e.g. python nslookup.py www.example.com
    elif is_valid_dns_request():
        handle_dns_query()
    else:
        print("ERROR: Invalid input!\nValid inputs:")
        print("\t1. python nslookup.py <domain name>")
        print("\t2. python nslookup.py -type=PTR <ip address>")


if __name__ == "__main__":
    main()
