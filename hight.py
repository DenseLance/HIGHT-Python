def list_to_byte(lst):
    byte = 0
    for bit in lst:
        byte = (byte << 1) | bit
    return byte

def rotate_bits(x, n): # shift bits leftward
    return ((x << n) % 256) | (x >> (8 - n))

def whitening_key_generation(MK):
    WK = [None] * 8
    for i in range(4):
        WK[i] = MK[i + 12]
        WK[i + 4] = MK[i]
    return WK

def constant_generation():
    s = [0, 1, 0, 1, 1, 0, 1]
    delta = [list_to_byte(s[::-1])]
    for i in range(1, 128):
        s.append(s[i + 2] ^ s[i - 1])
        delta.append(list_to_byte(s[i:i + 7][::-1]))
    return delta

def subkey_generation(delta, MK):
    SK = [None] * 128
    for i in range(8):
        for j in range(8):
            SK[16 * i + j] = (MK[(j - i) % 8] + delta[16 * i + j]) % 256
        for j in range(8):
            SK[16 * i + j + 8] =   (MK[(j - i) % 8 + 8] + delta[16 * i + j + 8]) % 256
    return SK

def encryption_key_schedule(MK):
    delta = constant_generation()
    WK = whitening_key_generation(MK)
    SK = subkey_generation(delta, MK)
    return WK, SK

def decryption_key_schedule(MK):
    delta = constant_generation()
    WK = whitening_key_generation(MK)
    SK = subkey_generation(delta, MK)[::-1]
    return WK, SK

def encryption_initial_transformation(P, WK):
    X_0 = [
        (P[0] + WK[0]) % 256,
        P[1],
        P[2] ^ WK[1],
        P[3],
        (P[4] + WK[2]) % 256,
        P[5],
        P[6] ^ WK[3],
        P[7]
    ]
    return X_0

def decryption_initial_transformation(C, WK):
    X_0 = [
        C[7],
        (C[0] - WK[4]) % 256,
        C[1],
        C[2] ^ WK[5],
        C[3],
        (C[4] - WK[6]) % 256,
        C[5],
        C[6] ^ WK[7]
    ]
    return X_0

def f_0(x):
    return rotate_bits(x,1) ^ rotate_bits(x,2) ^ rotate_bits(x,7)

def f_1(x):
    return rotate_bits(x,3) ^ rotate_bits(x,4) ^ rotate_bits(x,6)

def encryption_round_function(i, X_i, SK):
    X_j = [
        X_i[7] ^ ((f_0(X_i[6]) + SK[4 * i + 3]) % 256),
        X_i[0],
        (X_i[1] + (f_1(X_i[0]) ^ SK[4 * i])) % 256,
        X_i[2],
        X_i[3] ^ ((f_0(X_i[2]) + SK[4 * i + 1]) % 256),
        X_i[4],
        (X_i[5] + (f_1(X_i[4]) ^ SK[4 * i + 2])) % 256,
        X_i[6]
    ]
    return X_j

def decryption_round_function(i, X_i, SK):
    X_j = [
        X_i[1],
        (X_i[2] - (f_1(X_i[1]) ^ SK[4 * i + 3])) % 256,
        X_i[3],
        X_i[4] ^ ((f_0(X_i[3]) + SK[4 * i + 2]) % 256),
        X_i[5],
        (X_i[6] - (f_1(X_i[5]) ^ SK[4 * i + 1])) % 256,
        X_i[7],
        X_i[0] ^ ((f_0(X_i[7]) + SK[4 * i]) % 256)
    ]
    return X_j

def encryption_final_transformation(X_32, WK):
    C = [
        (X_32[1] + WK[4]) % 256,
        X_32[2],
        X_32[3] ^ WK[5],
        X_32[4],
        (X_32[5] + WK[6]) % 256,
        X_32[6],
        X_32[7] ^ WK[7],
        X_32[0]
    ]
    return C

def decryption_final_transformation(X_32, WK):
    D = [
        (X_32[0] - WK[0]) % 256,
        X_32[1],
        X_32[2] ^ WK[1],
        X_32[3],
        (X_32[4] - WK[2]) % 256,
        X_32[5],
        X_32[6] ^ WK[3],
        X_32[7]
    ]
    return D

def encryption_transformation(P, WK, SK):
    X_i = encryption_initial_transformation(P, WK)
    for i in range(32):
        X_i = encryption_round_function(i, X_i, SK)
    C = encryption_final_transformation(X_i, WK)
    return C

def decryption_transformation(C, WK, SK):
    X_i = decryption_initial_transformation(C, WK)
    for i in range(32):
        X_i = decryption_round_function(i, X_i, SK)
    D = decryption_final_transformation(X_i, WK)
    return D

def hight_encryption(P, MK):
    WK, SK = encryption_key_schedule(MK)
    C = encryption_transformation(P, WK, SK)
    return C

def hight_decryption(C, MK):
    WK, SK = decryption_key_schedule(MK)
    D = decryption_transformation(C, WK, SK)
    return D
