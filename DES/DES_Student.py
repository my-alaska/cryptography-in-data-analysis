import textwrap
import binascii

import numpy as np
from matplotlib import pyplot as plt

#Funkcje pomocnicze
get_bin = lambda x, n: format(x, 'b').zfill(n)

# zamina ciągu bitów na wartość dziesiętną 
def bin2dec(binarybits):
    decimal = int(binarybits,2)
    return decimal

# zamina wartości dziesiętnej na ciąg bitów 
def dec2bin(decimal):
    binary4bits = bin(decimal)[2:].zfill(4)
    return binary4bits
# zamiana hex na bity 
def hex2bin(s):
    mp = {
        "0": "0000","1": "0001","2": "0010","3": "0011","4": "0100",
		"5": "0101","6": "0110","7": "0111","8": "1000","9": "1001",
		"A": "1010","B": "1011","C": "1100","D": "1101","E": "1110","F": "1111",
    }
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin

# zamiana bitów na hex
def bin2hex(s):
    mp = {
        "0000": "0","0001": "1","0010": "2","0011": "3","0100": "4",
		"0101": "5","0110": "6","0111": "7","1000": "8","1001": "9",
		"1010": "A","1011": "B","1100": "C","1101": "D","1110": "E","1111": "F",
    }
    hex = ""
    for i in range(0, len(s), 4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1]
        ch = ch + s[i + 2]
        ch = ch + s[i + 3]
        hex = hex + mp[ch]
    return hex

# zmiana hex na ASCI
def hex2ascii(hex_string):
#byte_array = bytearray.fromhex(hex_string)  
    byte_array = int(hex_string, 16).to_bytes((len(hex_string) + 1) // 2, byteorder="big")  
    ascii_string = byte_array.decode("ASCII")    
    return ascii_string

# zamiana znaków na wartości int
def intoIntArray(message: str):
    int_array = []
    mesg_array = list(message) 
    for i in mesg_array:
        int_array.append(ord(i))
    return int_array

# zamiana int w znaki 
def intoCharArray(message: []):
    mesg_char = []
    for i in message:
        mesg_char.append(chr(i))
    return mesg_char

def intListToBinStr(message_list):
    binary = []
    for x in message_list: 
        binary.append(get_bin(x, 8))
    binary_str = ""
    for x in binary:
        binary_str+=x 
    return binary_str

# przygotowanie danych dla funkcji F podstawienia bitowego 6/4
# podział wiadomości na 6-bitowe porcje 48/6 = 8 
def split48bits_in_6bits(XOR_48bits):
    list_of_6bits = textwrap.wrap(XOR_48bits,6)
    return list_of_6bits
# bity wyboru wiersza w SBox 
def get_first_and_last_bit(bits6):
    twobits = bits6[0] + bits6[-1] 
    return twobits
# bity wyboru wartości z kolumy w wierszu SBox
def get_middle_four_bit(bits6):
    fourbits = bits6[1:5] 
    return fourbits

def sbox_lookup(sboxcount,first_last,middle4):
    d_first_last = bin2dec(first_last)
    d_middle = bin2dec(middle4)
    # sbox_value = FAKEBOX[sboxcount][d_first_last][d_middle]
    sbox_value = SBOX[sboxcount][d_first_last][d_middle]
    return dec2bin(sbox_value)

PERMUTATION_TABLE = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
                     2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]

def apply_Permutation(permutation_table,sboxes_output):
    """ Scalony efekt użycia Sboksów poddawany jest zdefiniowanej permutacji"""
    permuted32bits = ""
    for index in permutation_table:
        permuted32bits += sboxes_output[index-1]
    return permuted32bits

def functionF(pre32bits, key48bits):
    #uzupełnij kod funkcji zgodnie z diagramem powyżej 
    final32bits = ''
    expanded_block = apply_Expansion(EXPANSION_TABLE, pre32bits)
    xored48bits = XOR(expanded_block,key48bits)
    sixbitslist = split48bits_in_6bits(xored48bits)
    
    for sboxi in range(0,8):
        bits6 = sixbitslist[sboxi]
        first_last = get_first_and_last_bit(bits6)
        middle4 = get_middle_four_bit(bits6)
        result = sbox_lookup(sboxi,first_last,middle4)
        final32bits+=result
    final32bits = apply_Permutation(PERMUTATION_TABLE, final32bits)
    return final32bits

INITIAL_PERMUTATION_TABLE = ['58 ', '50 ', '42 ', '34 ', '26 ', '18 ', '10 ', '2',
            '60 ', '52 ', '44 ', '36 ', '28 ', '20 ', '12 ', '4',
            '62 ', '54 ', '46 ', '38 ', '30 ', '22 ', '14 ', '6', 
            '64 ', '56 ', '48 ', '40 ', '32 ', '24 ', '16 ', '8', 
            '57 ', '49 ', '41 ', '33 ', '25 ', '17 ', '9 ', '1',
            '59 ', '51 ', '43 ', '35 ', '27 ', '19 ', '11 ', '3',
            '61 ', '53 ', '45 ', '37 ', '29 ', '21 ', '13 ', '5',
            '63 ', '55 ', '47 ', '39 ', '31 ', '23 ', '15 ', '7']

INVERSE_PERMUTATION_TABLE = ['40 ', '8 ', '48 ', '16 ', '56 ', '24 ', '64 ', '32',
                 '39 ', '7 ', '47 ', '15 ', '55 ', '23 ', '63 ', '31',
                 '38 ', '6 ', '46 ', '14 ',  '54 ', '22 ', '62 ', '30',
                 '37 ', '5 ', '45 ', '13 ', '53 ', '21 ', '61 ', '29',
                 '36 ', '4 ', '44 ', '12 ', '52 ', '20 ', '60 ', '28',
                 '35 ', '3 ', '43 ', '11 ', '51 ', '19 ', '59 ', '27', 
                 '34 ', '2 ', '42 ', '10 ', '50 ', '18 ', '58 ', '26',
                 '33 ', '1 ', '41 ', '9 ', '49 ', '17 ', '57 ', '25']

def apply_permutation(P_TABLE, PLAINTEXT):
    permutated_M = ""
    for index in P_TABLE:
        permutated_M += PLAINTEXT[int(index)-1]
    return permutated_M

def split64bits_in_half(binarybits):
    return binarybits[:32],binarybits[32:]

PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2, 41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

EXPANSION_TABLE = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]

SBOX = [
# Box-1
[
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
],
# Box-2

[
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
],

# Box-3

[
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]

],

# Box-4
[
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
],

# Box-5
[
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
],
# Box-6

[
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]

],
# Box-7
[
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
],
# Box-8

[
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
]

]

FAKEBOX = [
    [
        [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1] for line in box
    ] for box in SBOX
]

# xoor dla ciągu bitów równej długości
def XOR(bits1,bits2):
    xor_result = ""
    for index in range(len(bits1)):
        if bits1[index] == bits2[index]: 
            xor_result += '0'
        else:
            xor_result += '1'
    return xor_result

# rozszerzenie 32 do 48 bitów z użyciem tablicy 
def apply_Expansion(expansion_table,bits32):
    bits48 = ""
    for index in expansion_table:
        bits48 += bits32[index-1]
    return bits48

def apply_PC2(pc2_table,keys_56bits):
    keys_48bits = ""
    for index in pc2_table:
        keys_48bits += keys_56bits[index-1]
    return keys_48bits

def apply_PC1(pc1_table,keys_64bits):
    keys_56bits = ""
    for index in pc1_table:
        keys_56bits += keys_64bits[index-1] 
    return keys_56bits

def split56bits_in_half(keys_56bits):
    left_keys, right_keys = keys_56bits[:28],keys_56bits[28:]
    return left_keys, right_keys

#left56 , right56 = split56bits_in_half(keys_56bits)

def circular_left_shift(bits,numberofbits):
     shiftedbits = bits[numberofbits:] + bits[:numberofbits]
     return shiftedbits

round_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# generowanie kluczy rundowych 
def generate_keys(key_64bits):
    round_keys = list() 
    key56bits = apply_PC1(PC1,key_64bits)
    left28,right28 = split56bits_in_half(key56bits)
    for shift in round_shifts:
        left28,right28 = circular_left_shift(left28,shift),circular_left_shift(right28,shift)
        round_keys.append(apply_PC2(PC2, left28+right28))
    return round_keys


# szyfrowanie DES(wiadomosc, klucz)
def DES_encrypt(m,key,printing=False,swap_bit=False):
    chiper = ""
    pt_bits = m
    if swap_bit:
        key = key[:10] + str(1 - int(key[10])) + key[11:]

    k_bits = key
    roundKeys = generate_keys(k_bits)
    p_plaintext = apply_permutation(INITIAL_PERMUTATION_TABLE,pt_bits)
    L,R = split64bits_in_half(p_plaintext)



    old_perm = L+R
    total_sum = [0 for _ in old_perm]

    all_ciphers = []
    for round in range(16):
        all_ciphers.append(old_perm)
        newL = R
        newR = XOR(functionF(R,roundKeys[round]),L)
        R_changes = "".join(["1" if a!=b else "0" for (a,b) in zip(R,newR) ])
        R = newR
        L = newL

        perm = L + R
        # printing
        if printing:
            print("change in R: ",len([r for r in R_changes if r == "1"]))

            xor = "".join(["1" if a!=b else "0" for (a,b) in zip(old_perm,perm) ])
            for i,l in enumerate(xor):
                if l == "1": total_sum[i] += 1
            print("ciphertext change:",xor)
        old_perm = perm
    all_ciphers.append(old_perm)

    # printing
    if printing:
        print(total_sum)

    plt.bar([i for i in range(len(total_sum))],total_sum)
    plt.show()

    cipher = apply_permutation(INVERSE_PERMUTATION_TABLE,R+L)
    return cipher, all_ciphers


# zaimplementuj deszyfrowanie DES(szyfrogram, klucz w odwrotnej kolejnosci)     
def DES_decrypt(s,klucz):
    message = ""
    pt_bits = s
    k_bits = klucz[:64]
     
    roundKeys = generate_keys(k_bits)
    p_plaintext =  apply_permutation(INITIAL_PERMUTATION_TABLE,pt_bits)
    L,R = split64bits_in_half(p_plaintext)
    for round in range(15,-1,-1):
        newL = R
        newR = XOR(functionF(R,roundKeys[round]),L)
        R = newR
        L = newL 
    message = apply_permutation(INVERSE_PERMUTATION_TABLE,R+L)
    return message    

if __name__ == "__main__":
    M =   "alamakot"
    key = "HelloWorld"
    binary_key = intListToBinStr(intoIntArray(key))
    #binary_key = "1111111111111111111111111111111111111111111111111111111111111111"
    pt = intListToBinStr(intoIntArray(M))
    print("Wiadomość ASCI    :", M)
    print("Klucz ASCI        :", key)
    print("Wiadomośc 64-bitów:", pt)
    print("Klucz 64-bitowy   :", binary_key[:64])

    print("="*30 + "\n")
    print("ENCRYPTION")
    ciphertext, all_ciphers = DES_encrypt(pt, binary_key[:64])

    ciphertext2, all_ciphers2 = DES_encrypt(pt, binary_key[:64],swap_bit=True)


    for c1,c2 in zip(all_ciphers,all_ciphers2):
        xor = "".join(["1" if a != b else "0" for (a, b) in zip(c1, c2)])
        print(xor)

    print("\n" + "=" * 64)

    subkeys = generate_keys(binary_key)
    # print("podklucze:")
    # print("\n".join(subkeys))
    print("Szyfrogram        :", ciphertext)
    encrypted = DES_decrypt(ciphertext, binary_key[:64])
    print("Zdeszyfrowano'bin':", encrypted)
    print("sprawdzenie xor   :", XOR(pt, encrypted))
    print("Zdeszyfrowano'dec':", bin2dec(encrypted))
    print("Zdeszyfrowano'hex':", bin2hex(encrypted))
    print("Zdeszyfrowano ASCI:", hex2ascii(bin2hex(encrypted)))
