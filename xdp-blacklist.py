#!/usr/bin/python

import sys
from bcc import BPF

def usage():
    print("Usage: {0} <interface>".format(sys.argv[0]))
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    device = sys.argv[1]
    bpf = BPF(src_file="xdp-blacklist.c")
    xdp_main = bpf.load_func("xdp_main", BPF.XDP)
    bpf.attach_xdp(device, xdp_main)
    input("Press enter to terminate...")
    bpf.remove_xdp(device)
