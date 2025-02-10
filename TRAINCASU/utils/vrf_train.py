import serial
import time
import hmac
import hashlib
import struct
import threading
import binascii
from datetime import datetime, timedelta

def unframe_message(message):
	return message[message.index(b'~')+2:message[message.index(b'~')+1]+message.index(b'~')+2]

def frame_message(msg_type, snd_id, auth_req, seq, hash_idx, hash, cur_time):
	return b'~\x19'+msg_type+snd_id+auth_req+seq+hash_idx+hash+cur_time

def hmac_sha256(key, message):
    byte_key = binascii.unhexlify(key)
    return hmac.new(byte_key, message, hashlib.sha256).digest()

def reverse_endian(orig):
    return ''.join(sum([(c,d,a,b) for a,b,c,d in zip(*[iter(orig)]*4)], ()))


#----------------- Main Script ----------------#


SLACK = 1000
ATTESTTIME = 5000
KEY = "0123456789abcdef0000000000000000"
HASH = b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
HASH_IND = b'\x4F\x00\x00\x00'
NETHEIGHT = 1	
TREQ = 13
THASH = 30
LMT = b'\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x05'

ports = ['/dev/ttyUSB3', '/dev/ttyUSB2']
devs = ['rata', 'rata']
hashes = []
ATTEST = []
FAIL = []
NOREP = []
baud = 9600
TIME = None


def calculate_hmacs(ms_bytes):
	global hashes
	for dev in devs:
		if dev == 'casu':
			hashes.append(hmac_sha256(reverse_endian(KEY), b'HOST'+ms_bytes+HASH))
		elif dev == 'rata':
			hashes.append(hmac_sha256(reverse_endian(KEY), b'HOST'+ms_bytes+HASH+LMT))
	return hashes


def ms_to_little_endian(ms):
	total_ms = ms * 1.6
	byte_sequence = int(total_ms).to_bytes(4,byteorder='little')
	return byte_sequence

def start_train(ms):
	global TIME
	ms_bytes = ms_to_little_endian(float(ms/100))
	calculate_hmacs(ms_bytes)
	cur_time = time.time()
	write_all_serials(b'\x01\x00HOST\x4F\x00\x00\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'+ms_bytes+b'\x7d')
	print(" ")
	print("======================================================================")
	print(" ")
	print(f'Current Time: {datetime.fromtimestamp(cur_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}')
	print(f'Attest time set to {datetime.fromtimestamp(cur_time+(ms/1000)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}')
	print(" ")
	print("======================================================================")
	print(" ")
	while(TIME == None):
		a = 1
	time.sleep((ms/1000)/5)
	print(" ")
	print("======================================================================")
	print(f'===========ACCEPTING UNTIL {datetime.fromtimestamp(TIME+((ms+SLACK)/1000)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}====================')
	print("======================================================================")
	print(" ")
	while(time.time() - TIME < ((ms+SLACK)/1000) and len(NOREP)>0):
		a = 1
	print(" ")
	print("======================================================================")
	print("============================FINAL RESULTS=============================")
	print("======================================================================")
	print(" ")
	print(f"NoRep =  [{', '.join(NOREP)}]")
	print(f"Attest = [{', '.join(ATTEST)}]")
	print(f"Fail = [{', '.join(FAIL)}]")
	print(" ")
	print("======================================================================")




serial_connections = []
for port in ports:
	try:
		ser = serial.Serial(port, baud, timeout=0.5)
		serial_connections.append(ser)
	except serial.SerialException as e:
		print(f"Error opening serial port {port}: {e}")


def write_to_serial(ser, message):
	try:
		ser.write(message)
	except serial.SerialException as e:
		printf(f"Error writing to serial port {ser.port}: {e}")

def write_all_serials(msg):
	threads = []
	for ser in serial_connections:
		thread = threading.Thread(target=write_to_serial, args=(ser, msg))
		threads.append(thread)
		thread.start()
	for thread in threads:
		thread.join()

def read_from_serial(ser):
    last_message_time = None  # Initialize the last message time
    global TIME
    try:
        while True:
            if ser.in_waiting > 0:
                message = ser.readline()  # Remove decode().strip() to keep raw message
                #print(message)
                current_time = time.time()
                if last_message_time is not None:
                    time_since_last_message = current_time - last_message_time
                    if (((ATTESTTIME+SLACK)/1000) > time_since_last_message):
                        print(f'AttREP recieved from {ser.port} at time {datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}: {message}')
                        print("validating attREP...")
                        if (message[-32:] == (hashes[ports.index(ser.port)])):
                            print(f'AttRep of {ser.port} validated successfully')
                            ATTEST.append(ser.port)
                            NOREP.remove(ser.port)
                        else:
                            print(f'AttRep of {ser.port} NOT validated successfully')
                            NOREP.remove(ser.port)
                            FAIL.append(ser.port)
                else:
                    TIME = time.time()
                    print(f"AttREQ sent to {ser.port}: {message}")

                last_message_time = current_time
    except serial.SerialException as e:
        print(f"Error reading from serial port {ser.port}: {e}")

def read_all_serials():
	threads = []
	for ser in serial_connections:
		thread = threading.Thread(target=read_from_serial, args=(ser,))
		threads.append(thread)
		thread.start()
	return threads


print(" ___________  ___  _____ _   _  ______ ________  ________")
print("|_   _| ___ \/ _ \|_   _| \ | | |  _  \  ___|  \/  |  _  |")
print("  | | | |_/ / /_\ \ | | |  \| | | | | | |__ | .  . | | | |")
print("  | | |    /|  _  | | | | . ` | | | | |  __|| |\/| | | | |")
print("  | | | |\ \| | | |_| |_| |\  | | |/ /| |___| |  | \ \_/ /")
print("  \_/ \_| \_\_| |_/\___/\_| \_/ |___/ \____/\_|  |_/\___/ ")
print("======================================================================")
print(" ")
print("    -------- To begin, add your device(s) to ports on line 37-------- ")
print(" ")
print("======================================================================")
print(" ")
time.sleep(1.5)
print("Initializing Attest, Fail, and NoRep")
#time.sleep(0.5)
print("Attest = {}")
#time.sleep(1)
print("Fail = {}")
#time.sleep(1)
print(f"NoRep =  [{', '.join(ports)}]")
#time.sleep(1)
for x in ports:
	NOREP.append(x)
reading_threads = read_all_serials()
#start_tran(((NETHEIGHT*TREQ)+THASH)) about 50ms... Too fast to really demo anything
start_train(5000)	#5 second
