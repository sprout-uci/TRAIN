import serial
import time
import hmac
import hashlib
import struct

def unframe_message(message):
	return message[message.index(b'~')+2:message[message.index(b'~')+1]+message.index(b'~')+2]

def frame_message(msg_type, snd_id, auth_req, seq, hash_idx, hash, cur_time):
	return b'~\x19'+msg_type+snd_id+auth_req+seq+hash_idx+hash+cur_time


#----------------- Main Script ----------------#

##### UART / SERIAL PORT CONFIGURATION

## Modify based on your machine & connection
dev = '/dev/ttyUSB1' ## ubuntu syntax
# dev = 'COM4'		 ## windows syntax
## BAUD Rate USB-UART
baud = 9600
## serial python objcet
ser = serial.Serial(dev, baud, timeout=0.5)

## Setup initiaal 
chal_size = 32
challenge = get_init_challenge(chal_size)

challenge = [x.to_bytes(1,byteorder='big') for x in challenge]
challenge = b''.join(challenge)

METADATA_SIZE = 6
#####

key_size = 32

key = [0,0,0,0,0,0,0,0,
       0,0,0,0,0,0,0,0,
       0,0,0,0,0,0,0,0,
       0,0,0,0,0,0,0,0]
key = [x.to_bytes(1,byteorder='big') for x in key]
key = b''.join(key)

## internal variables
max_log_size = 256
sim_idx = 0
report_num = 0
last = 0

## Timing variables
total_time = 0
runtime_rounds = []

print(" ")
print(header)
print(" ")
print("-------- To begin, press \"Program device\" in Vivado")
print("======================================================================")
print(" ")


while last == 0:
	print("Waiting \'for\' prv")
	ackByte = b'\x61'
	readyByte = b'\x30'
	testByte = b'\x66'
	readyB = b'\x00'
	echo = b'\xff'

	print(ser.read())
	ser.write(b'\x61\x20\x20\x20\x20')		#ack + epoch time
	time.sleep(1)

	ser.write(b'\x01\x00HOST\x9a\n\xc9\xd1\\\x0f\x11\xff\x8bC\xc0\x02\r\xaa\xa7\xf1\x15\xfcu\xe1r\xc5^*\xf9~\x87\x0b\xb7\xe6\x868\x00\x00\x00\x01\x4F\x00\x00\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x09\x00\x00\x00}')
	print(ser.read())

	while(1):
		print(ser.read())
		a = 1
