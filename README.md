# xdp-blacklist

A simple XDP (eXpress Data Path) program to block IPs (IPv4 | IPv6)

## Usage

```
$ wget https://www.blocklist.de/downloads/export-ips_all.txt -O all.txt
$ sudo python xdp-blacklist.py [interface] all.txt
```
