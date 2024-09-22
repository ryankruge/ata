# MiTM ATA (All-Things-ARP)
ATA is a penetration tool for simple usage within a command-line environment. Using this tool, you can intercept network traffic going to and from other devices on your local network. This combined with third-party software such as `WireShark` can be a highly effective combination. The potential information that can be gathered could be as useful as an email and password or as *meaningless* as encrypted TLS / SSL data over HTTPS.
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
Due to the way this program works, for packets to be routed to and from the target correctly you must enable IP routing on your network interface. To accomplish this in **Windows**, you must enter the following command into the terminal.
```
netsh INTERFACE_NAME ipv4 set global forwarding=enabled
```
```
netsh INTERFACE_NAME ipv6 set global forwarding=enabled
```

## Usage
This program is a great tool for capturing packets and harvesting sensitive information (*hypothetically*) without the knowledge of the target. I **DO NOT** condone the malicious use of this software as it should only be used with explicit concent from the target.

![Credential Stealing](https://i.imgur.com/U3zjBuZ.png)
