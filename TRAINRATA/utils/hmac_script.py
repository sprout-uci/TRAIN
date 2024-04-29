import hmac
import hashlib 
import binascii
import time

def hmac_sha256(key, message):
    byte_key = binascii.unhexlify(key)
    message = message.decode("hex")
    return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()

def reverse_endian(orig):
    return ''.join(sum([(c,d,a,b) for a,b,c,d in zip(*[iter(orig)]*4)], ()))

def swap_endianess(barray):

	for i in range(0, len(barray), 2):
		tmp = barray[i]
		barray[i] = barray[i+1]
		barray[i+1] = tmp
	return barray


def read_mem(filepath):
	out = []
	with open(filepath, 'r') as fp:
		lines = fp.readlines()
		for line in lines:
			if '@' not in line:
				continue
			mem = line.split()
			for i in range(1, len(mem)):
				out.extend(mem[i].decode('hex'))
	out = swap_endianess(out)
	out = bytearray(out)
	return out

#key = "0123456789abcdef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
key = "0123456789abcdef000000000000000000000000000000000000000000000000"
#key = "0123456789abcdef0000000000000000"
chal = "1111111111111111111111111111111111111111111111111111111111111111"
#chal = "11111111111111111111111111111111"

pmem = read_mem('../msp_bin/pmem.mem')
#ER_min = 0x03e
ER_min = 0x1024
ER_max = 0x1186
sw_data = binascii.hexlify(pmem[ER_min:ER_max])
print("pure sw data: ", sw_data)
header = "01a60001" + chal
tail = "E09AE09AE09AE09AE09AE09AE09AE09AE09AE09AE09AE09AE09AE09AE09AA000"

sw_data = reverse_endian(sw_data)
sw_data = header + sw_data + tail
sw_data = reverse_endian(sw_data)
t = time.time()
#dkey = hmac_sha256(reverse_endian(key), reverse_endian(chal))
#token = hmac_sha256(dkey, sw_data)
print("reverse key: ", reverse_endian(key))
hmac = hmac_sha256(reverse_endian(key), sw_data)

byte_key = binascii.unhexlify(key)
message = sw_data.decode("hex")
print("message: ", message, ", size: ", hex(len(message)))

print("time taken for verifier to comupte atoken", time.time() - t)
print("size of sw ", hex(len(sw_data)/2))
print("size of sw except for header: ", hex(ER_max - ER_min))

print("Key: ", key)
print("Chal: ", chal)
print("ER:", sw_data)

#dkey_list = []
#i = 0
#while (i < len(dkey)):
#	dkey_list.append("0x{0}".format(dkey[i:i+2]))
#	i += 2
#
#print("DKey:", dkey)
#print(', '.join(dkey_list).lower())

sw_list = []
i = 0
while (i < len(sw_data)):
	sw_list.append("0x{0}".format(sw_data[i:i+2]))
	i += 2

hmac_list = []
i = 0
while (i < len(hmac)):
	hmac_list.append("0x{0}".format(hmac[i:i+2]))
	i += 2

print("size of sw: ", hex(len(sw_list)))
print("sw_list:")
print(', '.join(sw_list).lower())

print("hmac:", hmac)
print(', '.join(hmac_list).lower())