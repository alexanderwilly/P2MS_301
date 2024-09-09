# Name = Alexander Willy Johan
# UOW ID = 7907790
from Crypto.PublicKey import DSA

# Create a new DSA key
key = DSA.generate(1024)
f = open("public_key.pem", "wb")
f.write(key.publickey().export_key())
f.close()
