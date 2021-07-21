import idaapi, idc, idautils, binascii, struct

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

def retrieveStringFunctionArguments(functionCrossReference):

	stringDecryptCall = 0
	stringBlobSize = 0
	keyBlobAddress = 0
	stringBlobAddress = 0

	newAddress = functionCrossReference
	functionEnd = idc.get_func_attr(functionCrossReference, FUNCATTR_END)

	while True:

		nextAddress = idc.next_head(newAddress)

		if nextAddress >= functionEnd:
			return stringBlobAddress, keyBlobAddress, stringBlobSize

		if idc.print_insn_mnem(nextAddress) == "call":
			stringDecryptCall = get_operand_value(nextAddress, 0)
			break

		newAddress = nextAddress


	currentAddress = stringDecryptCall
	functionEnd = idc.get_func_attr(currentAddress, FUNCATTR_END)

	keyBlobAddress = idc.get_operand_value(stringDecryptCall, 0)
	stringBlobSize = idc.get_operand_value(idc.next_head(stringDecryptCall), 0)
	stringBlobAddress = idc.get_operand_value(idc.next_head(idc.next_head(stringDecryptCall)), 1)

	return stringBlobAddress, keyBlobAddress, stringBlobSize


def retrieveInjectStructFunctionArguments(functionCrossReference):

	pointerToStructure = 0
	structureItemCount = 0

	newAddress = functionCrossReference
	functionStart = idc.get_func_attr(functionCrossReference, FUNCATTR_START)

	while True:

		previousAddress = idc.prev_head(newAddress)

		if previousAddress < functionStart:
			break

		if idc.print_insn_mnem(previousAddress) == "mov" and idc.get_operand_type(previousAddress, 1) == idc.o_imm:
			pointerToStructure = idc.get_operand_value(previousAddress, 1)

			tempAddress = idc.prev_head(previousAddress)

			if idc.print_insn_mnem(tempAddress) == "inc":
				structureItemCount = 1
				break

		if idc.print_insn_mnem(previousAddress) == "push" and idc.get_operand_type(previousAddress, 0) == idc.o_imm:
				structureItemCount = idc.get_operand_value(previousAddress, 0)
				break

		newAddress = previousAddress

	return pointerToStructure, structureItemCount



def locateInjectStructFunctions(listOfCoreFunctions):
	
	for coreFunction in listOfCoreFunctions:

		functionCrossReferences = locateFunctionCrossReferences(coreFunction)

		stringBlobAddress, keyBlobAddress, stringBlobSize = retrieveStringFunctionArguments(coreFunction)
		stringBlobData = readBytesFromFile(stringBlobAddress, stringBlobSize)
		keyBlobData = readBytesFromFile(keyBlobAddress, 0x5A)
		
		for functionReference in functionCrossReferences:

			pointerToStructure, structureItemCount = retrieveInjectStructFunctionArguments(functionReference)
			structureData = readBytesFromFile(pointerToStructure, structureItemCount * 21)

			splitStructures = [structureData[i:i + 21] for i in range(0, 21 * structureItemCount, 21)]

			for hookStructure in splitStructures:
				dllNameOffset = struct.unpack("I", hookStructure[0:4])[0]
				apiNameOffset = struct.unpack("I", hookStructure[4:8])[0]
				replaceOffset = struct.unpack("I", hookStructure[8:12])[0]
				originaOffset = struct.unpack("I", hookStructure[12:16])[0]

				decryptedDll = decryptString(dllNameOffset, stringBlobData, stringBlobSize, keyBlobData).strip("\x00")
				decryptedAPI = decryptString(apiNameOffset, stringBlobData, stringBlobSize, keyBlobData)

				print (decryptedDll + "::" + decryptedAPI)


				addStringComment(decryptedDll, pointerToStructure + (i * 21))
				addStringComment(decryptedAPI, pointerToStructure + (i * 21) + 4)

				idc.set_name(replaceOffset, "replace" + decryptedAPI)
				idc.set_name(originaOffset, "original" + decryptedAPI)


def injectStructAutomation(*coreFunctionList):

	locateInjectStructFunctions(coreFunctionList)
