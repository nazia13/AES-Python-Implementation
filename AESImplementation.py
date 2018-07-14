# Implementation of AES on Python
import math
import numpy as np
import random



#============================================================================================================
#============================================================================================================
#============================================================================================================

def CreateMessage(): 
	StateMatrix_PT 			    = np.zeros(StateSize)
	choice 						=  input("(1) Random Message, (2) Input Message? ")
	if choice   				== 1:
		PlainText_Length 		= input("Please Enter size of message to be encrypted: ")
		GenBits 				= random.getrandbits(PlainText_Length)
		PT 						= "{0:032x}".format(GenBits, 'x')
	else:
		PT 						=  raw_input("What is your Message? (Please Input a Hex String)")
	
	# print "The Message To be Encrypted is: ", PT
	return PT


def GenerateMasterKey():
	choice 					   =  input("(1) Random Key, (2) Input Key? ")
	if choice   			   == 1:
		GenBits 			   = random.getrandbits(128)
		MainKey    	 		   = "{0:032x}".format(GenBits, 'x')
	else:
		MainKey 			   = raw_input("What is your Key? (Please Input a Hex String)")
	
	# print "The Key to be used is: ", MainKey
	# print "\n"
	return MainKey


def PrepareStateMatrix(HexStringRecieved):
	StateMatrix 			   = np.zeros(StateSize)
	for i in range(0, len(HexStringRecieved), 2):
		ByteExtracted                       = int(HexStringRecieved[i:i + 2], 16)
		StateMatrix[(i / 2) % 4, i / 8]     = ByteExtracted
	return StateMatrix


def KeyExpansionAlgorithm(Key, KeyMatrix, CurrentRoundIndex):
	StateSize   			  = (4, 4)
	StateMatrix 			  = np.zeros(StateSize)
	ArrayIndex  			  = 0

#============================================================================================================
#============================================================================================================
	# Step 0 of KeyGen : Creating State Matrix and adding the previous Round Key to KeyMatrix
	StateMatrix = PrepareStateMatrix(Key)
	for i in range(0, len(Key), 2):
		ByteExtracted                       = int(Key[i:i + 2], 16)
		KeyMatrix[CurrentRoundIndex, i / 2] = ByteExtracted

#============================================================================================================
#============================================================================================================
	# Step 1 of KeyGen : Rotate the Last column
	LastColumnInStateMatrix = StateMatrix[:, 3]
	LastColumnInStateMatrix = np.roll(LastColumnInStateMatrix, -1)

#============================================================================================================
#============================================================================================================
	# Step 2 of KeyGen : Substitute the Rotated Column with the corresponding
	# SBOX values
	for element in LastColumnInStateMatrix:
		CorrespondingColumnInSBOX              = int(element / 16)
		CorrespondingRowInSBOX                 = int(element % 16)
		LastColumnInStateMatrix[ArrayIndex]    = sboxTable[CorrespondingColumnInSBOX, CorrespondingRowInSBOX]

#============================================================================================================
#============================================================================================================
	# Step 3 of KeyGen : For the first element, XOR with the Round Constant
		if ArrayIndex == 0:
			RoundMultiplier                     = "{0:08b}".format(int(RoundConstants[CurrentRoundIndex]))
			FirstElementinLastColumn            = "{0:08b}".format(int(LastColumnInStateMatrix[ArrayIndex]))
			LastColumnInStateMatrix[ArrayIndex] = int(FirstElementinLastColumn, 2) ^ int(RoundMultiplier, 2)
		ArrayIndex = ArrayIndex + 1

#============================================================================================================
#============================================================================================================
	# Step 4 of KeyGen : XOR each column of the State Matrix with the LatestGeneratedColumn
	ArrayToXORWith = np.zeros(4)
	ArrayToXORWith = LastColumnInStateMatrix

	for ColumnSelector in xrange(0, 4):
		ColumnToXor = StateMatrix[:, ColumnSelector]
		for ElementSelector in xrange(0, 4):
			ElementToXORfromStateMatrix                  = "{0:08b}".format(int(ColumnToXor[ElementSelector]))
			ElementToXORfromPrevColumn                   = "{0:08b}".format(int(ArrayToXORWith[ElementSelector]))
			StateMatrix[ElementSelector, ColumnSelector] = int(ElementToXORfromStateMatrix, 2) ^ int(ElementToXORfromPrevColumn, 2)
		ArrayToXORWith	= StateMatrix[:, ColumnSelector]

	NewRoundKey = (StateMatrix.transpose()).reshape(1, 16)
	RoundKeyHexString = ""

	for DecimalCharacter in NewRoundKey[0]:
		HexCharacter = "{0:02x}".format(int(DecimalCharacter))
		RoundKeyHexString = RoundKeyHexString + HexCharacter
	


	return RoundKeyHexString, KeyMatrix

#============================================================================================================

def SetupPhase():
	CurrentRoundIndex = 0
	KeyMatrix         = np.zeros(KeyMatrixSize)
	
	MainKey 		  = GenerateMasterKey()
	#MainKey           = "000102030405060708090a0b0c0d0e0f"			# Input MainKey in Hex String Format
	
	for CurrentRoundIndex in xrange(0, 11):
		MainKey, KeyMatrix = KeyExpansionAlgorithm(MainKey, KeyMatrix, CurrentRoundIndex)	
	
	# print "KeyMatrix \n", KeyMatrix
	# print "\n"
	return KeyMatrix  												# Obtaining RoundKeys in Decimal of Hex Format

#============================================================================================================



def Encrypt(PT,KeyMatrix):
	CurrentRoundIndex = 0
	RoundKeyHexString = ""

	StateMatrix_PT   = PrepareStateMatrix(PT)
	# print "PlainTextStateMatrix \n", StateMatrix_PT
	# print "\n"

	RoundKeyToBeUsed = KeyMatrix[CurrentRoundIndex,:]
	for DecimalCharacter in RoundKeyToBeUsed:
		HexCharacter = "{0:02x}".format(int(DecimalCharacter))
		RoundKeyHexString = RoundKeyHexString + HexCharacter

	# print "\n"
	# print "RoundKeyHexString", RoundKeyHexString
	RoundKeyStateMatrix = PrepareStateMatrix(RoundKeyHexString)
	

	# print "RoundKeyStateMatrix \n", RoundKeyStateMatrix
	# print "\n"



#Main Program Starts Here
KeyMatrixSize  = (11, 16)
StateSize      = (4, 4)

Plaintext 	   = np.zeros(16)
sbox           = np.zeros(256)
RoundConstants = np.zeros(10)
KeyMatrix      = np.zeros(KeyMatrixSize)

sbox[:]        = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
sboxTable      = sbox.reshape((16, 16))
RoundConstants = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x00]


KeyMatrix  = SetupPhase()
Plaintext  = CreateMessage()
CipherText = Encrypt(Plaintext, KeyMatrix) 
