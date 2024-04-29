def converter(input_string):
    # Prepend SOH character and null character
    hex_bytes = b'\x01\x00'
    
    # Convert each character to its hexadecimal representation
    for char in input_string:
        hex_bytes += char.encode('ascii')
    
    # Append closing curly brace character
    hex_bytes += b'\x7d'
    
    return hex_bytes
	
	
input_string = "Pavel love UART protocol"
result = converter(input_string)
print(result)


import hashlib

def calculate_sha256(data):
    # Convert data to bytes if it’s not already
    if isinstance(data, str):
        data = data.encode()

    # Calculate SHA-256 hash
    data = b'\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42'
    data = b'\x00\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x00\x00\x00\x01O\x00\x00\x00\x09\x00\x00\x00'

    sha256_hash = hashlib.sha256(data).digest()
    return sha256_hash

# Example usage:
input_data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
hash_value = calculate_sha256(input_data)
print("SHA-256 Hash:", hash_value)



import hmac
import hashlib 
import binascii
import time

def hmac_sha256(key, message):
    byte_key = binascii.unhexlify(key)
    #message = message.decode("hex")
    return hmac.new(byte_key, message, hashlib.sha256).digest().upper()

def reverse_endian(orig):
    return ''.join(sum([(c,d,a,b) for a,b,c,d in zip(*[iter(orig)]*4)], ()))

            #\x02 because rep now
            #\x01 because devid is (1)
sw_data = b'\x02\x01\x00\x00\x00\x9a\n\xc9\xd1\\\x0f\x11\xff\x8bC\xc0\x02\r\xaa\xa7\xf1\x15\xfcu\xe1r\xc5^*\xf9~\x87\x0b\xb7\xe6\x868\x00\x00\x00\x01\x4F\x00\x00\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x09\x00\x00\x00'

key = "0123456789abcdef000000000000000000000000000000000000000000000000"
hmac = hmac_sha256(reverse_endian(key), sw_data)
print(hmac)