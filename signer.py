#Roberto Perez Mendoza
#Assignment 3

#################################################################################
# This file gives an example of generating a digital signature and verifying it
#################################################################################

import os, random, struct
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode


#extra library added
from binascii import unhexlify

##################################################
# Loads the RSA key object from the location
# @param keyPath - the path of the key
# @return - the RSA key object with the loaded key
##################################################
def loadKey(keyPath):
	
	# The RSA key
	key = None
	
	# Open the key file
	with open(keyPath, 'r') as keyFile:
		
		# Read the key file
		keyFileContent = keyFile.read()
		
		# Decode the key
		decodedKey = b64decode(keyFileContent)
		
		# Load the key
		key = RSA.importKey(decodedKey)

	# Return the key
	return key
		

##################################################
# Signs the string using an RSA private key
# @param sigKey - the signature key
# @param string - the string
##################################################
def digSig(sigKey, string):
	
	# TODO: return the signature of the file
	try:
		signature = sigKey.sign(string, '')
	except:
		print("Error!!! Can't sign public key")
		exit(-1)
	return signature

##########################################################
# Returns the file signature
# @param fileName - the name of the file
# @param privKey - the private key to sign the file with
# @return fileSig - the file signature
##########################################################
def getFileSig(fileName, privKey):
	
	# TODO:
	# 1. Open the file
	# 2. Read the contents
	# 3. Compute the SHA-512 hash of the contents
	# 4. Sign the hash computed in 4. using the digSig() function
	# you implemented.
	# 5. Return the signed hash; this is your digital signature
	with open(fileName, "r") as file:
		contents = file.read()
		dHash = SHA512.new(contents).hexdigest()
		sHash = digSig(privKey, dHash)

	return sHash

###########################################################
# Verifies the signature of the file
# @param fileName - the name of the file
# @param pubKey - the public key to use for verification
# @param signature - the signature of the file to verify
##########################################################
def verifyFileSig(fileName, pubKey, signature):
	
	# TODO:
	# 1. Read the contents of the input file (fileName)
	# 2. Compute the SHA-512 hash of the contents
	# 3. Use the verifySig function you implemented in
	# order to verify the file signature
	# 4. Return the result of the verification i.e.,
	# True if matches and False if it does not match
	with open(fileName, "r") as file:
		contents = file.read()
		dHash = SHA512.new(contents).hexdigest()
		sig = loadSig(signature)
		
	return verifySig(dHash, sig, pubKey)

############################################
# Saves the digital signature to a file
# @param fileName - the name of the file
# @param signature - the signature to save
############################################
def saveSig(fileName, signature):


#STOP
	# TODO: 
	# Signature is a tuple with a single value.
	# Get the first value of the tuple, convert it
	# to a string, and save it to the file (i.e., indicated
	# by fileName)
	with open(fileName, "w") as file:
		file.write(str(signature[0]))

###########################################
# Loads the signature and converts it into
# a tuple
# @param fileName - the file containing the
# signature
# @return - the signature
###########################################
def loadSig(fileName):
	
	# TODO: Load the signature from the specified file.
	# Open the file, read the signature string, convert it
	# into an integer, and then put the integer into a single
	# element tuple
	with open(fileName, "r") as file:
		sString = file.read()
		signature = int(sString)

	return (signature,)

#################################################
# Verifies the signature
# @param theHash - the hash 
# @param sig - the signature to check against
# @param veriKey - the verification key
# @return - True if the signature matched and
# false otherwise
#################################################
def verifySig(theHash, sig, veriKey):
	
	# TODO: Verify the hash against the provided
	# signature using the verify() function of the
	# key and return the result
	if veriKey.verify(theHash, sig) == True:
		print("Verification Matches!")
	else:
		print("Verification does not match!")

################################################################################
##########################EXTRA CREDIT PORTION AES##############################
################################################################################
#function to set the key
def set_key(key):
	if len(key) == 32:
		k = str(unhexlify(key))
		return k
	else:
		print("You enter a length of " + format(len(key))+ "Keys out of 32 hex required")
		exit(-1)

#############################ENCRYPTION#########################################
def aesenc(inputFileName, signature, key):
	ciphertext = ""
	plaintext = str(signature[0])
	plaintext = str(len(plaintext)) + "==" + plaintext 

	with open(inputFileName, "r") as file:
		plaintext += file.read()
	
		##########################################
		# Add padding to the plaintext
		# @param plaintext - the original plaintext
		# @return - the padded plaintext
		###########################################	
#Edited this part to make small encryption work
	#leftOverBlockSize = len(plaintext) % 16
	pad = 16 - len(plaintext) % 16
	while len(plaintext) % 16 != 0:
		plaintext += chr(pad) 
	
	new_val = AES.new(key, AES.MODE_ECB)
	
	for i in range(0, len(plaintext), 16):
			ciphertext += new_val.encrypt(plaintext[i:i+16])
	
	outputFileName = "enc_" + inputFileName[:]
	with open(outputFileName, "w") as file:
		file.write(ciphertext)
	
	return outputFileName

################################DECRYPTION#####################################
def aesdec(inputFileName, key):
	plaintext = ""
	ciphertext = ""

	with open(inputFileName, "r") as file:
		ciphertext += file.read()
	
	new_val = AES.new(key, AES.MODE_ECB)
	
	for i in range(0, len(ciphertext), 16):
		plaintext += new_val.decrypt(ciphertext[i:i+16])
	
	signatureLength = plaintext.split("==")[0]
	signature = plaintext[len(signatureLength) + len("==") : len(signatureLength) + int(signatureLength) + len("==")]
	plaintext = removePadding(plaintext[len(signatureLength) + len("==") + len(signature):])

	
	textdec = "enc_"
	start = inputFileName.find(textdec)
	if start > -1:
		outputFileName = "dec_" + inputFileName[start + len(textdec):]
	else:
		outputFileName = "dec_" + inputFileName

	with open(outputFileName, "w") as file:
		file.write(plaintext)
	
	return (outputFileName, (int(signature),))

#=======Remove Padding============================
#=======From previous assignment==================
def removePadding(plaintext):
		npad = ord(plaintext[-1])
		#added CHECK
		padChar = plaintext[-1]
		isPad = False
		if npad > 0 and npad < 16:
			if npad == 1 and plaintext[-2] != padChar:
				#for one padding
				return plaintext[:len(plaintext)-1]

			for i in range(2, npad):
				if plaintext[-i] != padChar:
					isPad = False
		if isPad:
			return plaintext[:len(plaintext)-npad]
		return plaintext
################################################################################
############################END OF EXTRA CREDIT#################################
################################################################################

# The main function
def main():
	
	# Make sure that all the arguments have been provided
	if len(sys.argv) != 5:
		print("USAGE:  " + sys.argv[0] + " <KEY FILE NAME> <SIGNATURE FILE NAME> <INPUT FILE NAME> <sign/verify>\n")
		print("Below can be used to test the extra credit portion:\n")
		print("EXTRA CREDIT USAGE:	" + sys.argv[0] + " <KEY FILE NAME> <AES KEY> <INPUT FILE NAME> <sign-aes/verify-aes>\n")
		exit(-1)
	
	# The key file
	keyFileName = sys.argv[1]
	
	# Signature file name
	sigFileName = sys.argv[2]
	
	# The input file name
	inputFileName = sys.argv[3]
	
	# The mode i.e., sign or verify
	mode = sys.argv[4]

	# TODO: Load the key using the loadKey() function provided.
	key = loadKey(keyFileName)

	# We are signing
	if mode == "sign":

		# TODO: 1. Get the file signature
		#       2. Save the signature to the file
		sig = getFileSig(inputFileName, key)
		saveSig(sigFileName, sig)
		print("Signature saved to file: {}" .format(sigFileName))
		
	# We are verifying the signature
	elif mode == "verify":
		
		# TODO Use the verifyFileSig() function to check if the
		# signature signature in the signature file matches the
		# signature of the input file
		verifyFileSig(inputFileName, key, sigFileName)

################################################################################
#########################SIGN EXTRA CREDIT PORTION##############################
################################################################################	
	elif mode == "sign-aes":
		k = set_key(sys.argv[2].replace(" ", ""))
		#get the file signature
		sig = getFileSig(inputFileName, key)
		#Save the signature to the file
		outFile = aesenc(inputFileName, sig, k)
		print("Encryption saved to: " + format(outFile))

################################################################################
#########################VERIFY EXTRA CREDIT PORTION############################
################################################################################
	elif mode == "verify-aes":
		k = set_key(sys.argv[2].replace(" ", ""))
		(outFile, sig) = aesdec(inputFileName, k)

		with open(outFile, "r") as file:
			contents = file.read()
			dHash = SHA512.new(contents).hexdigest()
		# signature signature in the signature file matches the
		# signature of the input file
			verifySig(dHash, sig, key)
		print("Decryption saved to: " + format(outFile))
	else:
		print("Error!!! Invalid mode:" + format(mode))
##############END OF SIGN AND VERIFY EXTRA CREDIT###############################

### Call the main function ####
if __name__ == "__main__":
	main()
