# netfilter_kmod

Very easy netfilter kmod example that only drop ICMP packets.

## Usage

```bash
make
insmod dropicmp.ko
ping 8.8.8.8 -c 3
rmmod dropicmp
```
