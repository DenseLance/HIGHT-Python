from hight import encryption_key_schedule, decryption_key_schedule, encryption_transformation, decryption_transformation

# TEST CASE
MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
P = [0xD7, 0x6D, 0x0D, 0x18, 0x32, 0x7E, 0xC5, 0x62]
expected_C = [0xE4, 0xBC, 0x2E, 0x31, 0x22, 0x77, 0xE4, 0xDD]

# MAIN CODE
print("Plaintext:", [hex(byte)[2:].upper() for byte in P])

assert not len(P) % 8 and P
assert all(0 <= byte <= 0xFF for byte in P)
assert len(MK) == 16
assert all(0 <= byte <= 0xFF for byte in MK)

def ecb_hight_encryption(P, MK):
    WK, SK = encryption_key_schedule(MK)
    C = encryption_transformation(P, WK, SK)
    for block in range(8, len(P), 8):
        C += encryption_transformation(P[block:block + 8], WK, SK)
    return C

C = ecb_hight_encryption(P, MK)

print("Encrypted bytes:", [hex(byte)[2:].upper() for byte in C])

assert C == expected_C

def ecb_hight_decryption(C, MK):
    WK, SK = decryption_key_schedule(MK)
    D = decryption_transformation(C, WK, SK)
    for block in range(8, len(C), 8):
        D += decryption_transformation(C[block:block + 8], WK, SK)
    return D

D = ecb_hight_decryption(C, MK)

print("Decrypted bytes:", [hex(byte)[2:].upper() for byte in D])

assert D == P
