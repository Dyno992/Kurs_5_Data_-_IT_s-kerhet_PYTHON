from binascii import unhexlify


def xor_strings(s, t) -> bytes:
    return bytes([a ^ b for a, b in zip(s, t)])


def hextobyte():
    print()
    hex_msg1 = '391813c092a2d5ac9acb705dfe41be3df08de67d1145cbcc3f'
    hex_msg2 = '03adeae2c8c2f2336c8a8d312733c2456e76e0b2d9068adc3f'
    hex_msg3 = '72d0954e354045f09461dc4c911d0b58ff8963efb12c34303f'

    print('Hexadecimal 1: ', hex_msg1)
    print('Hexadecimal 2: ', hex_msg2)
    print('Hexadecimal 3: ', hex_msg3)

    print()

    bytearray_msg1 = unhexlify(hex_msg1)
    bytearray_msg2 = unhexlify(hex_msg2)
    bytearray_msg3 = unhexlify(hex_msg3)
    AliceKey = xor_strings(bytearray_msg2, bytearray_msg3)
    msg = xor_strings(AliceKey, bytearray_msg1)
    print(msg.decode('utf-8'))

    print('Byte array msg1: ', bytearray_msg1)
    print('Byte array msg2: ', bytearray_msg2)
    print('Byte array msg3: ', bytearray_msg3)



# def converttobyte():
# def one_xor_two_xor_three():


def main():
    return 0


hextobyte()

if __name__ == "__main__":
    main()
