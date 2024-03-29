from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii
import hashlib

# hardcoding DSA parameters g p and q

key_pem = "-----BEGIN PUBLIC KEY-----\n\
MIIBuDCCASwGByqGSM44BAEwggEfAoGBAPjcuAzUql5UJCUFtrmZCTIW2HwkF41p\n\
8wZErX4F67FdQ8tYdvxU96VpsWTR8Kc7g0hfo5JNvIMPDHuTXnkCENLAu1odr+fE\n\
MNuF2s32IHxm9b2gJOFbqVeC2ZyBl/RT5APS0ATURLsBFDh7nMdWYSA9lo/906H8\n\
O/3wxmY6Dl8nAhUAuG5JOmTQxi+ggVNc/ehK36s4kZECgYEAmG/a7utQN49O8GDC\n\
DIbjjNoCZagvVExw8s3TjONCNwnsO1UIYPj1KaKwfWasuWl9ukK1e5WNGDG1IrYC\n\
eIT88koWEtFeeaIOCbnLIk/b5wOYZGD8cohc1kmK38gMbsFO4ECKkheaMNSYpIyH\n\
jqb8DpBWTGIOO9OGXUK6HbntubQDgYUAAoGBANpiH1XiCC80c93WU5k/5XLUUF27\n\
vvLWz1czD2/vaOAC91CVK/AJuS6N1Ui/Ph9T6Uz1zDm+uDPglnblDGzQVSsUJNPM\n\
2nW3JQQNXNv01WswIQLZkwVoEzTNEpZgxGhA9SxOCaLEoCPgKKgUY5n+f++waYg1\n\
+LK3JBetsU5oMQws\n\
-----END PUBLIC KEY-----\n\
"

param_key = DSA.import_key(key_pem)
param = [param_key.g, param_key.p, param_key.q]

script = []
stack = []
key_list = []
sig_list = []
valid_signatures = 0
starting_num = 0
N = 0 # num of PK
M = 0 # num of sig
  

file = open("scriptSig.txt", "r")
for line in file:
	script.append(line.strip())
	M = M + 1
file.close()
M = M - 1 

file = open("scriptPubKey.txt", "r")
for line in file:
	script.append(line.strip())
	N = N + 1
file.close()
N = N - 3


# push all of signatures and public keys to stack
while len(script) != 1:
	 element = script.pop(0)
	 stack.append(element)

stack.pop() # pop off N

for x in range (N):
	key = stack.pop()
	key_list.append(key)

stack.pop() # pop off M

for x in range (M):
	sig = stack.pop()
	sig_list.append(sig)
	
#counter = 0

for sig_hex in sig_list:
	signature = binascii.unhexlify(sig_hex)
	#print("counter:", counter)
	
	for i in range(starting_num, N):
		#print("i:", i)
		#print("starting number:", starting_num)
		verified = False
		tup = param.copy()
		pubKey_hex = key_list[i]
		pubKey = int(pubKey_hex, 16)
		tup.insert(0, pubKey)
		key = DSA.construct(tuple(tup))
		message = b"CSCI301 Contemporary topic in security"
		hash_obj = SHA256.new(message)
		verifier = DSS.new(key, 'fips-186-3')
		try:
			verifier.verify(hash_obj, signature)
			# print("verified")
			verified = True
			valid_signatures += 1
		except ValueError:
			pass # do nothing
		finally:
			starting_num += 1
		
		if verified == True:
			# counter += 1
			break
	
if valid_signatures == M:
	print("1")
	print("Script is valid")
else:
	print("0")
	print("Script is not valid")
