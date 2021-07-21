import idaapi, idc, idautils, binascii

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


def locateStringOffset(functionAddress):

	stringOffset = 0

	previousAddress = functionAddress

	while True:

		previousAddress = idc.prev_head(previousAddress)

		if previousAddress <= functionAddress - 10:
			break

		if idc.print_insn_mnem(previousAddress) == "mov":
			if idc.get_operand_type(previousAddress, 0) == 1 and idc.get_operand_type(previousAddress, 1) == idc.o_imm:
				stringOffset = idc.get_operand_value(previousAddress, 1)
				return stringOffset

	return -1

def retrieveFunctionArguments(functionCrossReference):

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

	return stringBlobAddress, keyBlobAddress, stringBlobSize, specificStringOffset

def locateStringFunctions(listOfCoreFunctions):

	for coreFunction in listOfCoreFunctions:

		functionCrossReferences = locateFunctionCrossReferences(coreFunction)

		for functionReference in functionCrossReferences:

			stringBlobAddress, keyBlobAddress, stringBlobSize, specificStringOffset = retrieveFunctionArguments(functionReference)

			stringBlobData = readBytesFromFile(stringBlobAddress, stringBlobSize)
			keyBlobData = readBytesFromFile(keyBlobAddress, 0x5A)

			if specificStringOffset != 0:
				decryptedString = decryptString(specificStringOffset, stringBlobData, stringBlobSize, keyBlobData)
				print (decryptedString)
				pass

			functionStart = idc.get_func_attr(functionReference, FUNCATTR_START)

			nextFunctionCrossReferences = locateFunctionCrossReferences(functionStart)

			for nextFunctionReference in nextFunctionCrossReferences:

				stringOffset = locateStringOffset(nextFunctionReference)

				if stringOffset == -1:
					continue

				decryptedString = decryptString(stringOffset, stringBlobData, stringBlobSize, keyBlobData)
				
				addStringComment(decryptedString, nextFunctionReference)

def stringAutomation(*coreFunctionList):

	locateStringFunctions(coreFunctionList)


def manualStringDecrypt(stringDecryptWrapper, referenceAddress, targetOffset):

	stringBlobAddress, keyBlobAddress, stringBlobSize,_ = retrieveFunctionArguments(stringDecryptWrapper)

	stringBlobData = readBytesFromFile(stringBlobAddress, stringBlobSize)
	keyBlobData = readBytesFromFile(keyBlobAddress, 0x5A)

	decryptedString = decryptString(targetOffset, stringBlobData, stringBlobSize, keyBlobData)
	
	addStringComment(decryptedString, referenceAddress)
