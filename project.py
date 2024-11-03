from helpers import *

# This is the project file for the cryptanalysis project, which has some helper
# functions and classes for the project. Any files beginning with "secret" will
# be git ignored. Steps
# 1. Randomly generate five 16-bit round keys. 16 bits means 4 hex characters.
# 2. Encrypt 10,000 known 16-bit plaintexts using the S-Box and the round keys.
# 3. Send each other the 10,000 cyphertexts.
# 4. Follow Heys' tutorial for differential cryptanalysis to compute a table
#    (table 8) to get *one byte* of the *final* round key. It's probably worth
#    taking notes of what you do as you do it, so that it can be explained in a
#    report later.
# 5. Reveal to each other.


sbox = SBox(
    [
        0x0,
        0xF,
        0x7,
        0x4,
        0xD,
        0x2,
        0xC,
        0x1,
        0xA,
        0x6,
        0xC,
        0xB,
        0x9,
        0x5,
        0x3,
        0x8,
    ]
)
# This is the second DES S-Box
# https://en.wikipedia.org/wiki/DES_supplementary_material#Substitution_boxes_(S-boxes)


diff_table = difference_distribution_table(sbox)
print(f"Difference Distribution Table for S-Box ({sbox}):")
print(pretty_string_diff_table(diff_table))
print(f"Best difference characteristic: {best_difference_characteristic_path(sbox, 3)}")

key_1, key_2, key_3, key_4, key_5 = generate_round_keys()

spn = SPN(sbox, (key_1, key_2, key_3, key_4, key_5))

plaintext = generate_plaintexts()
ciphertext = spn.encrypt(plaintext)

write_secret_file("keys.txt", f"{key_1}\n{key_2}\n{key_3}\n{key_4}\n{key_5}")
write_secret_file("plaintexts.txt", "\n".join([str(p) for p in generate_plaintexts()]))
write_secret_file("ciphertexts.txt", "\n".join([str(c) for c in ciphertext]))
