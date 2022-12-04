from hight import encryption_key_schedule, decryption_key_schedule, encryption_transformation, decryption_transformation

# TEST CASE
MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
IV = [0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81]
P = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
expected_C = [0xCE, 0x15, 0x95, 0x08, 0x5A, 0x18, 0x8C, 0x28]

# MAIN CODE
print("Plaintext:", [hex(byte)[2:].upper() for byte in P])

assert not len(P) % 8 and P
assert all(0 <= byte <= 0xFF for byte in P)
assert len(IV) == 8
assert all(0 <= byte <= 0xFF for byte in IV)
assert len(MK) == 16
assert all(0 <= byte <= 0xFF for byte in MK)

def cbc_hight_encryption(P, IV, MK):
    WK, SK = encryption_key_schedule(MK)
    C = encryption_transformation([P_i ^ IV_i for P_i, IV_i in zip(P[:8], IV)], WK, SK)
    for block in range(8, len(P), 8):
        C += encryption_transformation([P_i ^ C_i for P_i, C_i in zip(P[block:block + 8], C[block - 8:block])], WK, SK)
    return C

C = cbc_hight_encryption(P, IV, MK)

print("Encrypted bytes:", [hex(byte)[2:].upper() for byte in C])

assert C == expected_C

def cbc_hight_decryption(C, IV, MK):
    WK, SK = decryption_key_schedule(MK)
    D = [C_i ^ IV_i for C_i, IV_i in zip(decryption_transformation(C[:8], WK, SK), IV)]
    for block in range(8, len(C), 8):
        D += [C_i ^ D_i for C_i, D_i in zip(decryption_transformation(C[block:block + 8], WK, SK), C[block - 8:block])]
    return D

D = cbc_hight_decryption(C, IV, MK)

print("Decrypted bytes:", [hex(byte)[2:].upper() for byte in D])

assert D == P
