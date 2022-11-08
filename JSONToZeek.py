# import json
from getHostAddress import getHostAddress


def getDestinationIPList(filename):
	"""
	Goes through MUD policy file and returns the allowed Destination IPv4 networks
	"""
	destinationIPList = []
	with open(filename, 'r') as mud_policy: #Didn't know this before, but 'with' automatically closes the file once the statement is exited.
		for line in mud_policy:
			stripped_line = line.strip()
			if "destination-ipv4-network" in stripped_line:
				ip_subnet = stripped_line.split(': ')[1] #IP Subnet is in string form
				destinationIPList.append(ip_subnet)
	return destinationIPList

#Test Statement. Seems to be working properly
# print(getDestinationIPList('amazonEchoMud.json'))

def createZeekTemplate(filename):
	"""
	Uses info from getDestinationIPList() to create a Zeek Template to find any anomalies in device communications.
	Requirement: JSON file MUST be kept inside the MUD Profiles folder, and must be named deviceNameMud.json (ex.amazonEchoMud.json)
	"""
	device_name = filename.split('Mud.')[0]
	print(device_name)
	checkWords = ("insert destination IPs", "insertDeviceName", "insert host address")
	replacements = (str(getDestinationIPList('MUDProfiles/'+ filename)), device_name, getHostAddress("Amazon Echo")) #the insert host address and getHostAddress code MAY NOT work
	#NEED TO REPLACE ABOVE LINE GETHOSTADDRESS DEVICE NAME WITH THE GENERIC DEVICE NAME AFTER FIGURING OUT NAME CHANGING ALGORITHM
	zeek_template = open("ZeekScriptTemplate.zeek", "rt")
	required_zeek_file = open(device_name +"Script.zeek", "wt")
	for line in zeek_template:
		for check, rep in zip(checkWords, replacements):
			line = line.replace(check, rep) # help from https://stackoverflow.com/questions/51240862/find-and-replace-multiple-words-in-a-file-python 
		required_zeek_file.write(line)
	zeek_template.close()
	required_zeek_file.close()

#test
createZeekTemplate('amazonEchoMud.json')
#getHostAddress("Amazon Echo")

