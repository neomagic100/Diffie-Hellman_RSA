# CIS 3362 Homework 6, Problem 6
# RSA decipher
#       Note: Several functions are designed for this specific problem and its
#             parameters in mind, and may not work for other sets of integers.
# Author: Michael Bernhardt
# Last Updated: October 31, 2021

import math

# Given Data
pub_key_n = 2765039178267668499020061841
pub_key_e = 922535452715757606722838121
ciphertext = [195038167899690250214751691, 2141711604222016557798536602, 1066548693211359835237653738,
              2317202622660662466588325232,
              2069834036680626018726058180, 2707920486321294216134630753, 112373083172823378545343444,
              1522415492040755362449248759, 2318712221747538782511464915, 2267946947965001933538435629]

# Constants
LETTERS_PER_BLOCK = 19
NUM_LETTERS = 26
A = ord('A')


# Calculate phi given of a list of prime integers
# Input: prime_list - list of 2 prime integer factors
# Output: phi(n)
def phi(prime_list):
    p = prime_list[0]
    q = prime_list[1]
    phi_pq = (p - 1) * (q - 1)
    print('phi(n) =', int(phi_pq))
    return phi_pq
    

# Determine if an integer is prime
# Input: n - integer being tested
# Output: True - n is prime
def is_prime(n):
    sqrt = int(n**0.5)

    if n % 2 == 0:
        return False

    for i in range(3, sqrt, 2):
        if n % i == 0:
            return False

    return True


# Find the two prime integers, p and q, that factor from n
#   using Pollard-Rho factoring
#   Adapted from pollardrho.py by Arup Guha
# Input: n - Integer input that is the product of 2 primes
# Output: list of factors (length 2)
def pollard_rho_factor(n):
    a, b, = 2, 2
    found_factors = []
    
    print('Starting Pollard-Rho factoring...')
    
    while True:
        # Break after 2 factors found
        if len(found_factors) > 1:
            break
            
        a, b = pollard_step(a, b, n)
        
        a_minus_b = a - b
        
        if a_minus_b < 0:
            a_minus_b += n
        
        factor = math.gcd(n, a_minus_b)
        
        if factor < n and factor >= 2:
            if factor not in found_factors:
                found_factors.append(factor)
            
        elif factor == n:
            return -1
    
    print('Done Pollard-Rho factoring. Found', found_factors)
    return found_factors


# Iterate a and b for the next step in the loop of pollard_rho_factor
# Input: a, b, n - Integers
# Output: a, b - Integers that have been interated
def pollard_step(a, b, n):
    a = (a * a + 1) % n
    b = (b * b + 1) % n
    b = (b * b + 1) % n
    return a,b
    
    
# Perform fast modular exponentiation
# Input: base, exp, mod - integers
# Output: result of mod expo
def fast_mod_expo(base, exp, mod):
    if mod <= 0:
        return None
    if exp == 0:
        return 1
    if exp % 2 == 0:
        num = fast_mod_expo(base, exp // 2, mod)
        return (num * num) % mod
    return (base * fast_mod_expo(base, exp - 1, mod)) % mod


# Convert a numerical message to its string equivalent
#   Adapted from RSA2BigInt.java by Arup Guha
# Input: m - integer representation of message string
#        blocksize - integer of blocksize (default 19)
# Output: msg - the string recovered
def convert_back(m, blocksize = LETTERS_PER_BLOCK):
    msg = ''
    
    for i in range(blocksize):
        leftover = m % NUM_LETTERS
        leftint = int(leftover)
        msg = chr(A + leftint) + msg
        m = m // NUM_LETTERS
        
    return msg


# Decipher a ciphertext integer
# Input: cipher_int - integer of ciphertext
#        key_d - integer value of private key d
#        n - the original prime used for encryption
# Output: The deciphered integer     
def decrypt(cipher_int, key_d, n):
    # M = C^d mod n
    return fast_mod_expo(cipher_int, key_d, n)


# Decipher the list of ciphertext integers
# Input: cipher_list - the list of ciphertext integers
#        key_d - integer value of private key d
#        n - the original prime used for encryption
# Output: the list of deciphered integers 
def decrypt_all(cipher_list, key_d, n):
    print('\nDeciphering integer ciphertext list...')
    msg_list = []
    
    for cipher in cipher_list:
        msg = decrypt(cipher, key_d, n)
        print('  ', msg)
        msg_list.append(msg)
        
    print()
    return msg_list


# Find the modular inverse of b^-1 mod n = 1
# Input: b - Integer finding the mod inverse of
#        n - Integer mod
# Output: The integer result to get result * b = 1 mod n
def mod_inv(b, n):
    coeff, new_coeff = 0, 1
    rem, new_rem = n, b
    
    # Loop until 0 remainder
    while new_rem != 0:
        quo = rem // new_rem
        coeff, new_coeff = new_coeff, coeff - quo * new_coeff
        rem, new_rem = new_rem, rem - quo * new_rem
        
    if coeff < 0:
        coeff += n
    
    return coeff


# main
#
if __name__ == '__main__':
    # Get the original p and q used by factoring pub_key_n with Pollard Rho factorization
    factors = pollard_rho_factor(pub_key_n)
    
    # Calculate phi(n)
    phi_n = phi(factors)
    
    # Calculate the mod inverse: e^-1 mod phi(n)
    priv_key_d = mod_inv(pub_key_e, phi_n)
    
    # Decrypt the integer list, M = C^d mod n
    plaintext_integers = decrypt_all(ciphertext, priv_key_d, pub_key_n)
    
    # Convert the list of plaintext integers to uppercase letters
    plaintext = ''
    plaintext = [convert_back(p) for p in plaintext_integers]
    plaintext = ''.join(plaintext)
    print('Converted back to string:\n')
    print(plaintext)

