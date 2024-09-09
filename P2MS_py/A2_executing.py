# Name = Alexander Willy Johan
# UOW ID = 7907790
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii
import sys

# Stack implementation
class Stack:
	def __init__(self):
		self.items = []
	
	def is_empty(self):
		return len(self.items) == 0
	
	def push(self, item):
		self.items.append(item)
	
	def pop(self):
		if not self.is_empty():
			return self.items.pop()
		else:
			raise IndexError("pop from an empty stack")
	
	def peek(self):
		if not self.is_empty():
			return self.items[-1]
		else:
			raise IndexError("peek from an empty stack")
		
	def size(self):
		return len(self.items)
	
	def __str__ (self):
	 return str(self.items)


def get_content_from_file(filename):
	print()
	filein = open(filename, "r")
	content = filein.read().strip()
	filein.close()
	
	print("Obtained contents from {}".format(filename))
	
	return content


def push_scriptSig_to_stack(scriptSig, stack):
	print()
	scriptSig_tokens = scriptSig.split(' ')
	print("Pushing signatures to stack...")
	
	count = 0
	while (len(scriptSig_tokens) != 0):
		# Ignore first OP
		if(count > 0):
			stack.push(scriptSig_tokens[0])
			print("Done pushing a signature to stack")
		scriptSig_tokens.pop(0)
		count += 1
			
	print("Done pushing all signatures to stack!")


def push_scriptPubKey_to_stack(message, scriptPubKey, stack):
	print()
	scriptPubKey_tokens = scriptPubKey.split(' ')
	print("Pushing public keys to stack...")
	while (len(scriptPubKey_tokens) != 0):
		pk = scriptPubKey_tokens[0]
		if pk[:2] == "OP":
			if pk[3:] == "CHECKMULTISIG":
				isAllValid = check_multi_sig(message, stack)
				print()
				# If the tally of valid signatures is equal to M 
				# after all the signatures have been checked,
				# then CHECKMULTISIG pushes a 1 onto the stack 
				# and the script is valid
				if (isAllValid):
					stack.push(1)
					print("CHECKMULTISIG pushes 1 to stack")
				else:
					stack.push(0)
					print("CHECKMULTISIG pushes 0 to stack")
				
			else:
				stack.push(pk[3:])
				print("Done pushing {} to stack".format(pk[3:]))
		
		
		else:
			stack.push(pk)
			print("Done pushing a public key to stack")
		scriptPubKey_tokens.pop(0)
	
	

def check_multi_sig(message, stack):
	print()
	temp = []
	
	# Pops off N, and then pops that number of public keys of the stack
	n = int(stack.pop())
	temp.append(n)
	print("Done popping '{}' from stack".format(n))
	
	for pk in range(n):
		temp.append( stack.pop() )
	print("Done popping {} public keys from stack".format(n))
	
	# Pops off M, and then pops that number of signatures of the stack
	m = int(stack.pop())
	temp.append(m)
	print("Done popping '{}' from stack".format(m))
	
	
	for sig in range(m):
		temp.append( stack.pop() )
	print("Done popping {} signatures from stack".format(m))
	print()
	
	
	start_sig = len(temp) - 1
	start_pk = (len(temp) - m - 1) - 1
	
	ok = 0
	s = 0
	
	# Compare each signature with each public key
	# If signature not match with public key, move on and check with the next public key
	# However, that public key will also be ignored for every subsequent signature
	
	# If matches, increment a tally and repeat for the next signature
	print("Total Signatures = {} and Total Public Keys = {}".format(m, n))
	
	# Get P, Q, and G
	f = open("pqg.txt", "r")
	pqg = f.read().split()
	f.close()
	
	key_p = int(pqg[0])
	key_q = int(pqg[1])
	key_g = int(pqg[2])
	while s < m:
		# Construct the key
		key_y = int(temp[start_pk - s], 16)
		tup = [key_y, key_g, key_p, key_q ]
		pub_key = DSA.construct(tup)
		hash_obj = SHA256.new(message)
		verifier = DSS.new(pub_key, 'fips-186-3')
		try:
			verifier.verify(hash_obj, binascii.unhexlify(temp[start_sig - s]))
			print("Signature {} with Public Key {}: The message is authentic.".format(s+1, start_pk-s))
			ok += 1
			s += 1
		except ValueError:
			print("Signature {} with Public Key {}: The message is not authentic.".format(s+1, start_pk-s))
			start_pk -= 1
			
	
	
	if (ok == m):
		print("All signatures have been checked, and valid!")
		return True
	else:
		print("All public keys have been checked, but none are valid with the current check signature!")
		return False



def main():
	message = b"CSCI301 Contemporary topic in security"
	
	
	# Take scriptPubKey and scriptSig from files
	scriptPubKey = get_content_from_file("scriptPubKey.txt")
	scriptSig = get_content_from_file("scriptSig.txt")
	
	# Script Execution
	stack = Stack()
	push_scriptSig_to_stack(scriptSig, stack)
	push_scriptPubKey_to_stack(message, scriptPubKey, stack)
	
	print("Stack now is =", stack)
	print("~~ Done! ~~")
	
	
main()
