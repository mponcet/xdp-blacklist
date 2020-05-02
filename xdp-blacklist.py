#!/usr/bin/python

import argparse
import ctypes as ct
from bcc import BPF
from netaddr import IPAddress,AddrFormatError
from socket import htons,htonl

be32_addr = ct.c_uint32     # IPv4 addr
in6_addr = ct.c_uint16 * 8  # IPv6 addr

def bpf_blacklist_insert(bpf, ip_str):
    try:
        ip = IPAddress(ip_str)
    except AddrFormatError:
        raise ValueError("{} is not a valid IP address".format(ip_str))

    # htons/htonl: use network byte order within kernel
    if ip.version == 4:
        blacklist = bpf["ipv4_blacklist"]
        key = be32_addr(htonl(ip.value))
    elif ip.version == 6:
        blacklist = bpf["ipv6_blacklist"]
        ip_htons = [htons(w) for w in ip.words]
        key = in6_addr(*ip_htons)

    try:
        blacklist[key] = ct.c_uint64(0)
    except:
        raise Exception("BFP_HASH full ({} entries)".format(len(blacklist)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", type=str, help="Attach XDP program to given interface")
    parser.add_argument("blocklist", help="Load blocklist from given file")
    args = parser.parse_args()
    interface = args.interface
    blocklist = args.blocklist

    bpf = BPF(src_file="xdp-blacklist.c")

    with open(blocklist, "r") as f:
        lines = f.readlines()
        for line in lines:
            ip = line.strip()
            try:
                bpf_blacklist_insert(bpf, ip)
            except ValueError as err:
                print(err)
                pass
            except Exception as err:
                print(err)
                break

    xdp_main = bpf.load_func("xdp_main", BPF.XDP)
    bpf.attach_xdp(interface, xdp_main)
    input("Press enter to terminate...")
    bpf.remove_xdp(interface)
