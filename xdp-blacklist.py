#!/usr/bin/python

import argparse
import ctypes as ct
from bcc import BPF
from netaddr import IPAddress,AddrFormatError
from socket import htonl

class KeyIPv4(ct.Structure):
    _fields_ = [("addr", ct.c_uint32)]


def bpf_blacklist_insert(bpf, ip_str):
    try:
        ip = IPAddress(ip_str)
    except AddrFormatError:
        raise ValueError("{} is not a valid IP address".format(ip_str))

    if ip.version == 4:
        blacklist = bpf["ipv4_blacklist"]
        key = KeyIPv4(htonl(ip.value))
    elif ip.version == 6:
        raise ValueError("IPv6 not implemented")

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
