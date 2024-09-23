# MiTM ATA (All-Things-ARP)
ATA is a penetration tool for simple usage within a command-line environment. This tool can intercept packets traversing between two devices on a local network. By combining this tool with third-party software such as **WireShark** it can form a highly effective combination. The amount of potentially sensitive information that can be gathered via this tool is mind-blowing. You could capture something as *useful* as login credentials or as *meaningless* as encrypted TLS / SSL data over HTTPS.
# Application Usage
## Arguments
- S T G - Source, target and gateway.
- I L D P - Network interface, attack duration, packet timeout, packet send interval.
- V VV - Verbose, more verbose.
## Requirements
This program requires the `scapy` and `colorama` libraries which can be installed via the command-line.
```
python -m pip install scapy
```
```
python -m pip install colorama
```
Due to the way this program works, for packets to be routed to and from the target correctly you must enable routing on your network interface. To accomplish this in **Windows**, you must enter the following command into the terminal.
```
netsh INTERFACE_NAME ipv4 set global forwarding=enabled
```
```
netsh INTERFACE_NAME ipv6 set global forwarding=enabled
```

## Usage

![Credential Stealing](https://i.imgur.com/U3zjBuZ.png)
This program is a great tool for capturing packets and harvesting sensitive information (*hypothetically*) without the knowledge of the target. I **DO NOT** condone the malicious use of this software as it should only be used with explicit concent from the target.
