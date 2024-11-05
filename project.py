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
        0,
        15,
        7,
        4,
        14,
        2,
        13,
        1,
        10,
        6,
        12,
        11,
        9,
        5,
        3,
        8,
    ]
)
# This is the second DES S-Box
# https://en.wikipedia.org/wiki/DES_supplementary_material#Substitution_boxes_(S-boxes)


diff_table = difference_distribution_table(sbox)
print(f"Difference Distribution Table for S-Box ({sbox}):")
print(pretty_string_diff_table(diff_table))
b = best_differential_characteristic(diff_table, 3)
if b is None:
    print("No characteristic found.")
    quit()
(
    best_input_diff,
    best_input_diff_final_round,
    best_output_diff,
    best_path_matrix,
    best_probability,
) = b
print(
    f"Best difference characteristic: {best_input_diff} -> {best_output_diff} with probability {best_probability}"
)
print(pretty_string_diff_characteristic_path(best_path_matrix))

key_1, key_2, key_3, key_4, key_5 = generate_round_keys()

spn = SPN(sbox, (key_1, key_2, key_3, key_4, key_5))

plaintext = generate_diffed_plaintexts(best_input_diff)
ciphertext = spn.encrypt(plaintext)

print("Test encryption / decryption:")
print(f"Plaintext: {plaintext[0]}")
print(f"Ciphertext: {ciphertext[0]}")
print(f"Decrypted: {spn.decrypt(ciphertext)[0]}")

write_secret_file("keys.txt", f"{key_1}\n{key_2}\n{key_3}\n{key_4}\n{key_5}")
write_secret_file("plaintexts.txt", "\n".join([str(p) for p in plaintext]))
write_secret_file("ciphertexts.txt", "\n".join([str(c) for c in ciphertext]))
