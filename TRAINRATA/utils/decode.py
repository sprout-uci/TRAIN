

#read multibyte message from
import struct

def decode_message(message):
    msg_type = message[0]  # Single byte value
   # print()
    values = list(map(lambda x: x, struct.unpack('<IIIIII', message[1:])))
    print(values)
    return values
   # return msg_type, values

# Example usage
m2 = b'\x00\x07\x00\x00\x00\t\x00\x00\x00dd\x00\x00\x0e\x00\x00\x00\xde\x00\x00\x00(\x00\x00\x00'



message = b'~\x19\x00\x07\x00\x00\x00\t\x00\x00\x00dd\x00\x00\x0e\x00\x00\x00\xde\x00\x00\x00(\x00\x00\x00'



def dec(message):
    print(message.index(b'~'))
    print(message[message.index(b'~')+1])
    print(message.index(b'~')+2)
    print(message[message.index(b'~')+1])
    print(message[message.index(b'~')+2:message[message.index(b'~')+1]+message.index(b'~')+2])
    return message[message.index(b'~')+2:message[message.index(b'~')+1]+message.index(b'~')+2]




#msg_type, 
dec(message)
values = decode_message(m2)
#print(msg_type)  # Output: 0
#print(values)    # Output: [2, 4, 100, 14, 222, 40]
