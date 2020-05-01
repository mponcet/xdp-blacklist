#!/usr/bin/python

import sys
import ctypes as ct
from bcc import BPF
from netaddr import IPAddress
from socket import htonl

class KeyIPv4(ct.Structure):
    _fields_ = [("addr", ct.c_uint32)]

def usage():
    print("Usage: {0} <interface>".format(sys.argv[0]))
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    device = sys.argv[1]
    bpf = BPF(src_file="xdp-blacklist.c")

    ipv4_blacklist = bpf["ipv4_blacklist"]
    google_dns = KeyIPv4(htonl(int(IPAddress("8.8.4.4"))))
    ipv4_blacklist[google_dns] = ct.c_uint64(0)

    xdp_main = bpf.load_func("xdp_main", BPF.XDP)
    bpf.attach_xdp(device, xdp_main)
    input("Press enter to terminate...")
    bpf.remove_xdp(device)
