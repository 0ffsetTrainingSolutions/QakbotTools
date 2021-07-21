import idaapi, idc, idautils, binascii, zlib, os, pefile


def setHexRaysComment(stringToComment, functionAddress):

	# https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c

	cfunc = idaapi.decompile(functionAddress)
	tl = idaapi.treeloc_t()
	tl.ea = functionAddress
	tl.itp = idaapi.ITP_SEMI
	cfunc.set_user_cmt(tl, stringToComment)
	cfunc.save_user_cmts() 

def addStringComment(stringToComment, functionAddress):

	# https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c

	try:
		idc.set_cmt(functionAddress, stringToComment, 0)
		setHexRaysComment(stringToComment, functionAddress)
	except Exception as E:
		print ("Can't set comments at address %x." % functionAddress)

		return

def readBytesFromFile(dataOffset, bytesToRead):
	
	return idaapi.get_bytes(dataOffset, bytesToRead)

def extractListOfHashes(xorValue, hashListAddress, hashListSize):

	retrievedDwordList = readBytesFromFile(hashListAddress, hashListSize)

	retrievedDwordList = [((struct.unpack("I", retrievedDwordList[i:i+4])[0] ^ xorValue) & 0xffffffff) for i in range(0, len(retrievedDwordList), 4)]

	return retrievedDwordList


def locateFunctionCrossReferences(functionAddress):

	return [addr.frm for addr in idautils.XrefsTo(functionAddress)]

def decryptString(stringOffset, stringBlob, stringBlobSize, keyBlob):

	loopCounter = 0
	offsetStringEnd = stringOffset
	decryptedString = ""

	if stringOffset < stringBlobSize:
		
		while stringBlob[offsetStringEnd] != keyBlob[offsetStringEnd % 0x5A]:
			offsetStringEnd += 1
		stringBlobSize = offsetStringEnd - stringOffset

		while loopCounter <= stringBlobSize:
			
			decryptedByte = ord(stringBlob[(stringOffset + loopCounter)]) ^ ord(keyBlob[(stringOffset + loopCounter) % 0x5A])
			decryptedString += chr(decryptedByte)

			loopCounter += 1

		return decryptedString

def parseRequiredDLLExports(dllName):

	# https://github.com/phracker/HopperScripts/blob/master/list-pe-exports.py
	dllFileName = os.path.join("C:\\Windows\\System32", dllName.strip("\x00"))

	if not os.path.exists(dllFileName):
		print ("Failed to locate DLL %s." % dllFileName)
		return False

	pe = pefile.PE(dllFileName, fast_load=True)

	pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
	return [dllExport.name for dllExport in pe.DIRECTORY_ENTRY_EXPORT.symbols]

def bruteForceCRC32Hash(dllName, locatedAPIHash):

	resolvedAPI = None
	listOfExports = parseRequiredDLLExports(dllName)
	listOfExports = filter(None, listOfExports)
	for dllExport in listOfExports:

		if zlib.crc32(dllExport) & 0xFFFFFFFF == locatedAPIHash:
			resolvedAPI = dllExport
			break

	if resolvedAPI == None:
		resolvedAPI = "ErrorLoadingCorrectAPI::%X" % (locatedAPIHash)

	apiString = "%s::%s" % (dllName.replace(".", "_"), resolvedAPI)

	return apiString

def retrieveStringFunctionArguments(functionCrossReference):

	specificStringOffset = 0
	stringBlobSize = 0
	keyBlobAddress = 0
	stringBlobAddress = 0

	currentAddress = functionCrossReference
	functionStart = idc.get_func_attr(functionCrossReference, FUNCATTR_START)

	previousAddress = idc.prev_head(currentAddress)

	stringBlobAddress = idc.get_operand_value(previousAddress, 1)

	previousAddress = idc.prev_head(previousAddress)

	if idc.print_insn_mnem(previousAddress) != "push":
			
		specificStringOffset = idc.get_operand_value(previousAddress, 1)
		previousAddress = idc.prev_head(previousAddress)

	stringBlobSize = idc.get_operand_value(previousAddress, 0)
	keyBlobAddress = idc.get_operand_value(idc.prev_head(previousAddress), 0)

	return stringBlobAddress, keyBlobAddress, stringBlobSize

def retrieveAPIFunctionArguments(functionCrossReference):
	
	dwordPointer = 0
	dllStringOffset = 0
	hashListSize = 0
	hashDataAddress = 0

	currentAddress = functionCrossReference
	functionStart = idc.get_func_attr(functionCrossReference, FUNCATTR_START)
	functionEnd = idc.get_func_attr(functionCrossReference, FUNCATTR_END)

	while True:

		previousAddress = idc.prev_head(currentAddress)
		
		if previousAddress <= functionStart:
			break

		if idc.print_insn_mnem(previousAddress) == "push":
			if idc.get_operand_type(previousAddress, 0) == idc.o_imm and idc.is_off0(idc.get_full_flags(previousAddress)):
				hashDataAddress = idc.get_operand_value(previousAddress, 0)

				previousAddress = idc.prev_head(previousAddress)

				if idc.print_insn_mnem(previousAddress) == "push":
					if idc.get_operand_type(previousAddress, 0) == idc.o_imm and not idc.is_off0(idc.get_full_flags(previousAddress)):
						hashListSize = idc.get_operand_value(previousAddress, 0)

						previousAddress = idc.prev_head(previousAddress)

						if idc.print_insn_mnem(previousAddress) == "push":
							if idc.get_operand_type(previousAddress, 0) == idc.o_imm and not idc.is_off0(idc.get_full_flags(previousAddress)):
								dllStringOffset = idc.get_operand_value(previousAddress, 0)

							else:
								dllStringOffset = 0

							break

		currentAddress = previousAddress


	newAddress = functionCrossReference

	while True:

		nextAddress = idc.next_head(newAddress)

		if nextAddress >= functionEnd:
			break	

		if idc.print_insn_mnem(nextAddress) == "mov" and idc.print_operand(nextAddress, 1) == "eax" and idc.is_off0(idc.get_full_flags(nextAddress)): 
			
			dwordPointer = idc.get_operand_value(nextAddress, 0)
			
			break

		newAddress = nextAddress


	return hashDataAddress, hashListSize, dllStringOffset, dwordPointer

def generateAPIStructure(dllName, resolvedAPIList):

	structureName = dllName + "_array"
	structID = idc.add_struc(-1, structureName, 0)

	for resolvedAPI in resolvedAPIList:
		idc.add_struc_member(structID, resolvedAPI, -1, FF_DWORD, -1, 4)

	return structureName

def locateAPIFunctions(xorValue, internalStringFunction, listOfCoreFunctions):

	for coreFunction in listOfCoreFunctions:

		functionCrossReferences = locateFunctionCrossReferences(coreFunction)

		for functionReference in functionCrossReferences:

			resolvedAPIList = []

			stringBlobAddress, keyBlobAddress, stringBlobSize = retrieveStringFunctionArguments(internalStringFunction)

			stringBlobData = readBytesFromFile(stringBlobAddress, stringBlobSize)
			keyBlobData = readBytesFromFile(keyBlobAddress, 0x5A)

			listOfHashes, hashListSize, dllStringOffset, dwordPointer = retrieveAPIFunctionArguments(functionReference)

			listOfConvertedHashes = extractListOfHashes(xorValue, listOfHashes, hashListSize)

			dllName = decryptString(dllStringOffset, stringBlobData, stringBlobSize, keyBlobData).strip("\x00")

			for convertedHash in listOfConvertedHashes:
				resolvedAPIString = bruteForceCRC32Hash(dllName, convertedHash)
				resolvedAPIList.append(resolvedAPIString)


			structureName = generateAPIStructure(dllName.replace(".", "_"), resolvedAPIList)

			idc.set_name(dwordPointer, structureName + "_ptr")
			idc.SetType(dwordPointer, structureName + "*")
			
def apiAutomation(xorValue, internalStringFunction, *coreFunctionList):

	locateAPIFunctions(xorValue, internalStringFunction, coreFunctionList)
