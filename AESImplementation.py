#Implementation of AES on Python
import math
import numpy as np
import random

def CreateMessage(k):
	plaintext = random.getrandbits(k)
	return plaintext

def SetMessageLength():
	plaintext_length = input("Please Enter size of message to be encrypted")
	return plaintext_length

def GenerateKey():
	Genbits = random.getrandbits(128)
	Key 	= format(Genbits,'x')
	return Key 

def KeyExpansionAlgorithm(Key, KeyMatrix):
	StateSize = (4,4)
	StateMatrix = np.zeros(StateSize)
	for i in range(0, len(Key), 2):
		ByteExtracted = int(Key[i:i+2],16)
		KeyMatrix[0,i/2] = ByteExtracted
		StateMatrix[i/8,(i/2)%4] = ByteExtracted

	# print KeyMatrix
	# print StateMatrix

	

	# print KeyMatrix
	# print Key

	
def Encrypt():
	PT_Length = SetMessageLength()
	PT = CreateMessage(PT_Length)
	K  = GenerateKey()
	s  = (11,16)
	KeyMatrix = np.zeros(s)
	KeyExpansionAlgorithm(K, KeyMatrix)


Encrypt()

