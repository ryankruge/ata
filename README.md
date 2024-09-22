# MiTM ATA (All-Things-ARP)
ATA is a penetration tool for simple usage within a command-line environment. Using this tool, you can intercept network traffic to other devices on your local network and view the packets from
third-party software such as `WireShark`. This information could be as useful as an email and password or as useless as encrypted TLS / SSL data over HTTPS.
# Application Usage
## Arguments
- S T G - Source, target and gateway.
- I L D P - Network interface, attack duration, packet timeout and packet send interval.
- V VV - Verbose and more verbose.
## Requirements
This program requires the `scapy` and `colorama` libraries which can be installed via the command-line.
```
python -m pip install scapy
```
```
python -m pip install colorama
```
Due to the way this program works, for packets to be forwarded to and from the target correctly you must enable IP routing on your networking interface. The command to do so is as follows.
```
netsh INTERFACE_NAME ipv4 set global forwarding=enabled
```
```
netsh INTERFACE_NAME ipv6 set global forwarding=enabled
```

## Usage
This program is a good tool for analysing packets and harvesting sensitive information without the knowledge of the target. I do not condone malicious use of this software and should only be used with explicit concent from the target.

![Credential Stealing](https://i.imgur.com/U3zjBuZ.png)
