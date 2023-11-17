from hight import encryption_key_schedule, decryption_key_schedule, encryption_transformation, decryption_transformation

# TEST CASE
MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
IV = [0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81]
P = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
expected_C = [0x10, 0x63, 0x42, 0xC7, 0x1E, 0x80, 0xAC, 0x0C]

# MAIN CODE
print("Plaintext:", [hex(byte)[2:].upper() for byte in P])

assert not len(P) % 8 and P
assert all(0 <= byte <= 0xFF for byte in P)
assert len(MK) == 16
assert all(0 <= byte <= 0xFF for byte in MK)

def cfb_hight_encryption(P, IV, MK):
    WK, SK = encryption_key_schedule(MK)
    C = [C_i ^ P_i for C_i, P_i in zip(encryption_transformation(IV, WK, SK), P[:8])]
    for block in range(8, len(P), 8):
        C += [C_i ^ P_i for C_i, P_i in zip(encryption_transformation(C[block - 8:block], WK, SK), P[block:block + 8])]
    return C

C = cfb_hight_encryption(P, IV, MK)

print("Encrypted bytes:", [hex(byte)[2:].upper() for byte in C])

assert C == expected_C

def cfb_hight_decryption(C, IV, MK):
    WK, SK = encryption_key_schedule(MK)
    D = [D_i ^ C_i for D_i, C_i in zip(encryption_transformation(IV, WK, SK), C[:8])]
    for block in range(8, len(C), 8):
        D += [C_i ^ C_j for C_i, C_j in zip(encryption_transformation(C[block - 8:block], WK, SK), C[block:block + 8])]
    return D

D = cfb_hight_decryption(C, IV, MK)

print("Decrypted bytes:", [hex(byte)[2:].upper() for byte in D])

assert D == P
