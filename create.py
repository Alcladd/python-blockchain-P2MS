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
param = [param_key.p, param_key.q, param_key.g]

print()

# N = num of PK
# M = num of sig
# N >= M
# num of PK >= num of sig
N = int(input("Enter number of public keys: "))
M = N + 1

while N < M:
	M = int(input("Enter number of signatures: "))

print()
scriptPubKey = []
scriptSig = []
key_list = []

# create scriptPubKey
scriptPubKey.append("OP_" + str(M))
for x in range(N):
	key = DSA.generate(1024, domain= param)
	key_list.append(key)
	y = key.y
	y_hex = hex(y)
	scriptPubKey.append(y_hex)

scriptPubKey.append("OP_" + str(N))
scriptPubKey.append("OP_CHECKMULTISIG")

# create scriptSig
scriptSig.append("OP_0")
for x in range(M):
	message = b"CSCI301 Contemporary topic in security"
	hash_obj = SHA256.new(message)
	signer = DSS.new(key_list[x], 'fips-186-3')
	signature = signer.sign(hash_obj)
	signature_hex = binascii.hexlify(signature).decode('ascii')
	scriptSig.append(signature_hex)
	
 
file = open("scriptPubKey.txt", "w")
for element in scriptPubKey:
	file.write("%s\n" %element)
file.close()

file = open("scriptSig.txt", "w")
for element in scriptSig:
	file.write("%s\n" %element)
file.close()

print("scriptPubKey and scriptSig has been generated")
