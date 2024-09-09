# Name = Alexander Willy Johan
# UOW ID = 7907795
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii

def read_keypem():
	f = open("public_key.pem", "rb")
	pk = f.read()
	f.close()
	return pk
	
def generate_key_pairs(key_pem, num_of_pub_keys):
	keys = []
	
	param_key = DSA.import_key(key_pem)
	param = [param_key.p, param_key.q, param_key.g]
	
	
	for kp in range(num_of_pub_keys):
		key = DSA.generate(1024, domain=param)
		keys.append(key)
		
		
	print("Done generating {} pairs of public/private keys".format(num_of_pub_keys))
		
	return keys
	
def generate_signatures(message, key_pairs, num_of_sig):
	signatures = []
	# The message is signed in each signature 
	# and they must be signed by the different private keys
	for sig in range(num_of_sig):
		hash_obj = SHA256.new(message)
		
		signer = DSS.new(key_pairs[sig], 'fips-186-3')
		signature = signer.sign(hash_obj)
		signatures.append( signature )
		
	print("Done generating {} signatures".format(num_of_sig))
	
	return signatures
	
def generate_scriptPubKey(n, m, keys):
	# OP_M <pubKey1> <pubKey2> <pubKeyN> OP_N OP_CHECKMULTISIG
	script_pub_key = "OP_{} ".format(m)
	for key in keys:
		
		script_pub_key += hex(key.y)[2:] + " "
		
		
	script_pub_key += "OP_{} OP_CHECKMULTISIG".format(n)
	
	
	fileout = open("scriptPubKey.txt", "w")
	fileout.write(script_pub_key)
	fileout.close()
	
	print("Done Generating scriptPubKey")
	

def generate_scriptSig(signatures):
	# OP_0 <sig1> <sig2> <sigM>
	script_sig = "OP_0 "
	for signature in signatures:
		script_sig += binascii.hexlify(signature).decode() + " "
	
	fileout = open("scriptSig.txt", "w")
	fileout.write(script_sig)
	fileout.close()
	
	print("Done Generating scriptSig")

def save_pqg(key):
	pqg = "{} {} {}".format(key.p, key.q, key.g)
	
	f = open("pqg.txt", "w")
	f.write(pqg)
	f.close()
	
	print("Done Saving G, P, and Q")
	
	

def main():
	key_pem = read_keypem()
	m = 0
	n = -1
	message = b"CSCI301 Contemporary topic in security"
	
	# N is equal to or greater than M
	# Keep entering m and n until the condition satisfied
	while( (n < m) or (n < 1) or (m < 1) ):
		try:
			m = int( input("Enter number of Signatures (M): ") )
			n = int( input("Enter number of Public Keys (N): ") )
		
			if (n < m):
				print("==> Please enter valid values")
				print("==> N must be greater than or equal to M")
			if(n < 1):
				print("==> N must be greater than or equal to 1")
			if(m < 1):
				print("==> M must be greater than or equal to 1")
				
		except ValueError:
			print("==> Please enter an integer")
	
	
	# Randomly generate N pairs of DSA 1024 bits public/private keys
	keys = generate_key_pairs(key_pem, n)
	
	# Generate M DSA signatures using the private keys generated
	signatures = generate_signatures(message, keys, m)
	
	# Generate scriptPubKey and scriptSig
	generate_scriptPubKey(n, m, keys)
	generate_scriptSig(signatures)
	
	save_pqg(keys[0])
	
	print("~~ Done! ~~")
	



main()
