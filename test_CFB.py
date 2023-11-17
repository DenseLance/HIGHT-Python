import io
import sys
sys.stdout, temp = io.StringIO(), sys.stdout
from hight_CFB import cfb_hight_encryption, cfb_hight_decryption
sys.stdout = temp

# Similar to how Crypto.Util.Padding is implemented
def pad(byte_list_to_pad: list, block_size: int):
    assert byte_list_to_pad[-1] != 13
    return byte_list_to_pad + list(b"\r") * (-len(byte_list_to_pad) % block_size)

def unpad(padded_byte_list: list):
    while padded_byte_list and padded_byte_list[-1] == 13:
        del padded_byte_list[-1]
    return padded_byte_list

# TEST CASE
MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
IV = [0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81]
P = list(open("test.txt", "rb").read())

# MAIN CODE
print("Plaintext:", [hex(byte)[2:].upper() for byte in P])

C = cfb_hight_encryption(pad(P, 8), IV, MK)
print("Encrypted bytes:", [hex(byte)[2:].upper() for byte in C])

D = unpad(cfb_hight_decryption(C, IV, MK))
print("Decrypted bytes:", [hex(byte)[2:].upper() for byte in D])

assert D == P
