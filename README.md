# tcpdump-u32-helper

https://macskas.github.io/tcpdump-u32-helper/

10+ years old little script. Sharing this just to help out others generate u32 rules based on tcpdump -x output.

for example:
```
user@server:~# tcpdump -n port 11211 -i lo -x
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes

15:09:20.337423 IP 127.0.0.1.51160 > 127.0.0.1.11211: Flags [S], seq 247267509, win 65495, options [mss 65495,sackOK,TS val 2568416280 ecr 0,nop,wscale 7], length 0
	0x0000:  4510 003c 68d0 4000 4006 d3d9 7f00 0001
	0x0010:  7f00 0001 c7d8 2bcb 0ebd 00b5 0000 0000
	0x0020:  a002 ffd7 fe30 0000 0204 ffd7 0402 080a
	0x0030:  9916 ec18 0000 0000 0103 0307
```

copy & paste the output to the html page. Then you can filter on tcp options even if its not supported by any iptables module.

