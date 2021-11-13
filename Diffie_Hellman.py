# CIS 3362 Homework 6, Problem 1
# Diffie-Hellman Key Exchange - show keys shared given public and secret keys
# Author: Michael Bernhardt


# Calculate X and Y, given public elements p and g, and private elements a and b
# Input: p - prime integer
#        g - primitive root mod p
#        a - secret key 1
#        b - secret key 2
# Output: The calculated X and Y shared between users of a and b
def init_key_calc(p, g, a, b):
    # Alice calculates X = g^a mod p and sends X to Bob
    x = mod_expo(g, a, p)

    # Bob calculates Y = g^b mod p and sends Y to Alice
    y = mod_expo(g, b, p)

    print(f'Alice calculates {g}^{a} mod {p} = {x}')
    print(f'Bob calculates {g}^{b} mod {p} = {y}')

    return x, y


# Calculate the shared key
# Input: x - calculated x from a
#        y - calculated y from b
#        p - prime integer
#       a, b - secret keys
# Output: Shared key
def calc_shared_key(x, y, p, a, b):
    alice_key = mod_expo(y, a, p)
    bob_key = mod_expo(x, b, p)

    # This should be returned as shared key
    if alice_key == bob_key:
        print(f'The shared key = {x}^{b} mod {p} = {y}^{a} mod {p} = {alice_key}')
        return alice_key

    # If error reached, print to debug
    else:
        return alice_key, bob_key


# Calculate modular exponentiation
# Input: integers base, exponent, mod
# Output: The calculated mod exponent
def mod_expo(base, exp, mod):
    # base case
    if exp == 0:
        return 1

    # even
    elif exp % 2 == 0:
        return (mod_expo(base, exp // 2, mod) * mod_expo(base, exp // 2, mod)) % mod

    # odd

    else:
        return (base * mod_expo(base, exp - 1, mod)) % mod


# Print the results to console
# Input: x and y that Alice and Bob calculate and share
#        key that is shared between them
def print_results(x, y, key):
    print()
    print(f'Alice sends Bob: {x}')
    print(f'Bob sends Alice: {y}')
    print(f'The shared key is: {key}')


def main():
    public_p, public_g = 53, 12
    secret_a, secret_b = 24, 43

    # Get respective X and Y to share
    X, Y = init_key_calc(public_p, public_g, secret_a, secret_b)

    # Calculate shared key
    key = calc_shared_key(X, Y, public_p, secret_a, secret_b)

    print_results(X, Y, key)


main()
