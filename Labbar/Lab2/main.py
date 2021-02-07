import math
import os
import random
import base64
import sys


def rabin_miller(num):
    s = num - 1
    t = 0

    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
        return True


class RSA:

    def bytes2int(self, byte_data):
        return int.from_bytes(byte_data, 'big', signed=False)

    def int2bytes(self, number: int, fill_size: int = 0) -> bytes:
        if number < 0:
            raise ValueError("The number needs to be an unsigned integer: %d" % number)

        bytes_required = max(1, math.ceil(number.bit_length() / 8))

        if fill_size > 0:
            return number.to_bytes(fill_size, 'big')

        return number.to_bytes(bytes_required, 'big')

    def encrypt(self, message, public_key):
        rsa = RSA()
        _, e, n = public_key
        int_message = rsa.bytes2int(message)
        return base64.b64encode(rsa.int2bytes(pow(int_message, e, n))).decode()

    def decrypt(self, message, private_key):
        rsa = RSA()
        message = base64.b64decode(message)
        int_message = rsa.bytes2int(message)
        _, d, n = private_key
        result = pow(int_message, d, n)
        bytes_result = rsa.int2bytes(result)
        print(bytes_result)
        return bytes_result.decode('utf-8')


class IsPrime:

    def is_prime(self, num):
        if num < 2:
            return False

        low_primes = [2, 3, 5, 7, 11, 13, 17,
                      19, 23, 29, 31, 37, 41,
                      43, 47, 53, 59, 61, 67,
                      71, 73, 79, 83, 89, 97,
                      101, 103, 107, 109, 113,
                      127, 131, 137, 139, 149,
                      151, 157, 163, 167, 173,
                      179, 181, 191, 193, 197,
                      199, 211, 223, 227, 229,
                      233, 239, 241, 251, 257,
                      263, 269, 271, 277, 281,
                      283, 293, 307, 311, 313,
                      317, 331, 337, 347, 349,
                      353, 359, 367, 373, 379,
                      383, 389, 397, 401, 409,
                      419, 421, 431, 433, 439,
                      443, 449, 457, 461, 463,
                      467, 479, 487, 491, 499,
                      503, 509, 521, 523, 541,
                      547, 557, 563, 569, 571,
                      577, 587, 593, 599, 601,
                      607, 613, 617, 619, 631,
                      641, 643, 647, 653, 659,
                      661, 673, 677, 683, 691,
                      701, 709, 719, 727, 733,
                      739, 743, 751, 757, 761,
                      769, 773, 787, 797, 809,
                      811, 821, 823, 827, 829,
                      839, 853, 857, 859, 863,
                      877, 881, 883, 887, 907,
                      911, 919, 929, 937, 941,
                      947, 953, 967, 971, 977,
                      983, 991, 997]

        if num in low_primes:
            return True

        for prime in low_primes:
            if num % prime == 0:
                return False

        return rabin_miller(num)

    @staticmethod
    def generate_large_prime(key_size=1024):
        prime = IsPrime()
        while True:
            num = random.randrange(2 ** (key_size - 1), 2 ** key_size)
            if prime.is_prime(num):
                return num


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def mod_inverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3

    return u1 % m


def generate_keys(key_size):
    p = IsPrime.generate_large_prime(key_size // 2)
    q = IsPrime.generate_large_prime(key_size // 2)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    while True:
        e = random.randrange(2 ** (key_size - 1), 2 ** key_size)
        if gcd(e, phi_n) == 1:
            break

    d = mod_inverse(e, phi_n)
    private_key = (d, n)
    public_key = (e, n)
    return public_key, private_key


def make_key_files(name, key_size):
    if os.path.exists(f'{name}_public.key') or os.path.exists(f'{name}_private.key'):
        sys.exit(
            f'WARNING: The file name {name}_public.key or {name}_private.key already exists!'
        )
    public_key, private_key = generate_keys(key_size)
    with open(f'{name}_public.key', 'w') as f:
        f.write(f'{key_size},{public_key[0]},{public_key[1]}')

    with open(f'{name}_private.key', 'w') as f:
        f.write(f'{key_size},{private_key[0]},{private_key[1]}')


def read_keys(name):
    if not os.path.exists(f'{name}_public.key') or not os.path.exists(f'{name}_private.key'):
        sys.exit(
            f'WARNING: The file name {name}_public.key or {name}_private.key does not exists!'
        )

    public_key = [int(value) for value in open(f'{name}_public.key').read().split(',')]
    private_key = [int(value) for value in open(f'{name}_private.key').read().split(',')]
    return public_key, private_key


def main():
    rsa = RSA()
    key_size = 2048
    print()
    name = input('Please Enter a key name: ')
    if not os.path.exists(f'{name}_public.key') or not os.path.exists(f'{name}_private.key'):
        make_key_files(name, key_size)

    public_key, private_key = read_keys(name)
    cipher = ''

    while True:
        print()
        print('#************¤¤¤¤¤¤¤¤************#')
        print('#------------¤ Menu ¤------------#')
        print('#************¤¤¤¤¤¤¤¤************#')
        print('1. ------> Encrypt Message')
        print('2. ------> Decrypt Message')
        print('3. ------> Encrypt a .txt file')
        print('4. ------> Decrypt a .txt file')
        print('9. ------> Exit')
        print()
        while True:
            menu_choice = input('> ')
            if menu_choice in '12349':
                break

        if menu_choice == '1':
            message = input("Enter message to encrypt: ")
            byte_msg = message.encode('utf-8')
            cipher = rsa.encrypt(byte_msg, public_key)
            print('Your Encrypted message is: ' + cipher)
            print()

        elif menu_choice == '2':
            clear_text = rsa.decrypt(cipher, private_key)
            print('Your Decrypted message is: ' + clear_text)
            print()

        elif menu_choice == '3':
            message = open("Encrypted_file.txt", encoding='utf-8').read()
            byte_msg_txt = message.encode('utf-8')
            c = rsa.encrypt(byte_msg_txt, public_key)
            open('Decrypted_file.txt', 'w').write(c)

        elif menu_choice == '4':
            message = open("Decrypted_file.txt", encoding='utf-8').read().encode('utf-8')
            clear_text_txt = rsa.decrypt(message, private_key)
            print(clear_text_txt.encode("utf-8"))

        elif menu_choice == '9':
            break


if __name__ == '__main__':
    main()