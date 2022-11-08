def getHostAddress(deviceName):
	"""
	Returns the Host Address (in IP format) given the device name. (Help from Lance Ding) for first bit of logic
	"""
	deviceListArr = []
	with open ("ListOfDevices.txt", "r") as fin:
		line = fin.readline()
		while line:
			line = line[1:-2] #shaved off the brackets
			line = line.split(",")
			#print(line)
			deviceListArr.append(line)
			line = fin.readline()

	deviceMacAddress = ""
	for line in deviceListArr:
		if line[0] == deviceName:
			deviceMacAddress = line[1]
			break
	print("<" + deviceMacAddress + ">")

	deviceMacAddress = deviceMacAddress.strip()
	with open ("16-09-23.csv", "r") as data:
		line = data.readline()
		while line:
			line = line.split(",")
			if line[3] == deviceMacAddress:
				#print(line)
				deviceIPAddress = line[5] #Maybe this line is wrong????
				break
			line = data.readline()
	return deviceIPAddress



	

print(getHostAddress("Amazon Echo"))
