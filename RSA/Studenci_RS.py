# https://www.dcode.fr/rsa-cipher

import random

# Algorytm Euklidesa (rozdział 4)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Rozszerzony algorytm Euklidesa (rozdział 4)
def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2- temp1* x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    
    if temp_phi == 1:
        return d + phi

# Test pierwszości (rozdział 4)
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Obie liczby muszą być pierwsze.')
    elif p == q:
        raise ValueError('p musi być różne od q')
    # n = pq
    n = p * q

    # Phi to wartość tocjentu dla n
    phi = (p-1) * (q-1)

    # Wybieram taką liczbę naturalną e, że e i phi(n) są względnie pierwsze
    e = 67 #random.randrange(1, phi)

    # Stosuję algorytm Euklidesa, aby sprawdzić, czy e i phi(n) są względnie pierwsze
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Wykorzystuję rozszerzony algorytm Euklidesa do wygenerowania klucza prywatnego
    d = multiplicative_inverse(e, phi)
    
    # Funkcja zwraca parę klucz publiczny i  klucz prywatny
    # Klucz publiczny to (e, n), klucz prywatny to (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    key, n = pk
    # Konwersja liter z tekstu jawnego (plaintext) na wartości liczbowe za pomocą a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    # Funkcja zwraca tablicę bajtów
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    # Odtwarzanie tekstu jawnego na podstawie klucza i szyfrogramu (ciphertext) za pomocą a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    # Funkcja zwraca tablicę bajtów w postaci łańcucha znaków
    return ''.join(plain)
    

if __name__ == '__main__':
    p = 29
    q = 31


    msg = "alamakota"
    public, private = generate_keypair(p, q)
    res = encrypt(public, msg)
    print(res)
    print(decrypt(private, res))

