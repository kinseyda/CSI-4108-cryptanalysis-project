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
        0xE,
        0x4,
        0xD,
        0x1,
        0x2,
        0xF,
        0xB,
        0x8,
        0x3,
        0xA,
        0x6,
        0xC,
        0x5,
        0x9,
        0x0,
        0x7,
    ]
)
# This is the second DES S-Box
# https://en.wikipedia.org/wiki/DES_supplementary_material#Substitution_boxes_(S-boxes)


diff_table = difference_distribution_table(sbox)
print(f"Difference Distribution Table for S-Box ({sbox}):")
print(pretty_string_diff_table(diff_table))
best_input_diff, best_output_diff = coordinate_of_max(
    diff_table, 16
)  # 16 will always appear in the top left

best_delta_p = [
    # Block((0, 0, 0, best_input_diff)),
    # Block((0, 0, best_input_diff, 0)),
    Block((0, best_input_diff, 0, 0)),
    # Block((best_input_diff, 0, 0, 0)),
]  # Not sure how exactly delta p is found, but it seems that it can go in any one single slot of the block

b = best_differential_characteristic(diff_table, 3, best_delta_p)
if b is None:
    print("No characteristic found.")
    quit()
(
    best_input_diff,
    best_input_diff_final_round,
    best_path_matrix,
    best_probability,
) = b
print(
    f"Best difference characteristic: {best_input_diff} -> {best_output_diff} with probability {best_probability:.2%}"
)
print(pretty_string_diff_characteristic_path(best_path_matrix))
print(f"Input to final round: {best_input_diff_final_round}")

key_1, key_2, key_3, key_4, key_5 = generate_round_keys()

spn = SPN(sbox, (key_1, key_2, key_3, key_4, key_5))
# spn = SPN(
#     sbox,
#     (
#         Block((1, 2, 3, 4)),
#         Block((5, 6, 7, 8)),
#         Block((9, 10, 11, 12)),
#         Block((13, 14, 15, 0)),
#         Block((1, 2, 3, 4)),
#     ),
# )

plaintext = generate_diffed_plaintexts(best_input_diff)
ciphertext = spn.encrypt(plaintext)
test_plain = Block((0xA, 0xB, 0xC, 0xD))
test_cipher = spn.encrypt([test_plain])[0]
test_decrypt = spn.decrypt([test_cipher])[0]
print("Test encryption / decryption:")
print(str(spn))
print(f"Plaintext: {test_plain}")
print(f"Ciphertext: {test_cipher}")
print(f"Decrypted: {test_decrypt}")

write_secret_file("keys.txt", f"{key_1}\n{key_2}\n{key_3}\n{key_4}\n{key_5}")
write_secret_file("plaintexts.txt", "\n".join([str(p) for p in plaintext]))
write_secret_file("ciphertexts.txt", "\n".join([str(c) for c in ciphertext]))


# Differential cryptanalysis
# analysis_plaintext = load_blocks("analysis_plaintexts.txt")
# analysis_cyphertext = load_blocks("analysis_ciphertexts.txt")

analysis_plaintext = load_blocks("secret_plaintexts.txt")
analysis_cyphertext = load_blocks("secret_ciphertexts.txt")


def find_last_key_byte(sbox: SBox, plaintexts: list[Block], cyphertexts: list[Block]):
    """
    Find a byte of the last key using differential cryptanalysis.
    """

    print("-" * 30 + f"Attacking S-Box ({sbox})" + "-" * 30)

    # Step 1: Compute the difference distribution table for the S-Box
    print("Computing difference distribution table...")
    diff_table = difference_distribution_table(sbox)

    # Find highest value, get the input difference that maps to it
    best_input_diff, best_output_diff = coordinate_of_max(
        diff_table, 16
    )  # 16 will always appear in the top left

    best_delta_p = [
        # Block((0, 0, 0, best_input_diff)),
        # Block((0, 0, best_input_diff, 0)),
        Block((0, best_input_diff, 0, 0)),
        # Block((best_input_diff, 0, 0, 0)),
    ]  # Not sure how exactly delta p is found, but it seems that it can go in any one single slot of the block

    print("Best input difference:")
    for i in best_delta_p:
        print(i)

    # Step 2: Compute the best difference characteristic for the S-Box
    print("Computing best differential characteristic...")
    best_characteristic = best_differential_characteristic(diff_table, 3, best_delta_p)

    if best_characteristic is None:
        print(
            "No characteristic with a good pair in the plaintexts / cyphertexts found."
        )
        return None

    (
        best_input_diff,
        final_round_input_diff,
        best_path,
        best_probability,
    ) = best_characteristic

    print("Best usable characteristic:")
    print(f"probability: {best_probability}")
    print(f"Best input difference: {best_input_diff}")
    print(f"Final round input difference: {final_round_input_diff}")
    print(pretty_string_diff_characteristic_path(best_path))

    # Step 3: Compute the probability of each partial subkey
    # Only need to check subkeys based on the sboxes that are affected in the last row of the path
    # Only try subkeys that affect the sboxes in the path. ie if the path includes the second and fourth sboxes, only try subkeys in range 0000 0000 0000 0001 to 0000 1111 0000 1111
    boxes_affected = output_boxes_affected(best_input_diff_final_round)
    subkeys_to_try = generate_partial_subkeys(
        boxes_affected[0], boxes_affected[1], boxes_affected[2], boxes_affected[3]
    )
    # For each cyphertext pair, try each subkey and see if the partial decryption matches the path
    print("Computing subkey probabilities...")
    subkey_probabilities = {}
    total = 0
    for (p0, c0), (p1, c1) in find_pairs_with_diff(
        best_input_diff, plaintexts, cyphertexts
    ):
        for subkey in subkeys_to_try:
            partial_decrypt0 = Block(tuple(sbox.decrypt_block(c0 ^ subkey)))
            partial_decrypt1 = Block(tuple(sbox.decrypt_block(c1 ^ subkey)))
            if partial_decrypt0 ^ partial_decrypt1 == final_round_input_diff:
                if subkey in subkey_probabilities:
                    subkey_probabilities[subkey] += 1
                    total += 1
                else:
                    subkey_probabilities[subkey] = 1
                    total += 1

    # Print a table showing the probability of each partial subkey
    print("Top 10 subkey probabilities:")
    for subkey, probability in sorted(
        subkey_probabilities.items(), key=lambda x: x[1], reverse=True
    )[:10]:
        print(f"{subkey}: {probability/total:.2%}")
    best_subkey, best_subkey_probability = max(
        subkey_probabilities.items(), key=lambda x: x[1]
    )
    return best_subkey


print(find_last_key_byte(sbox, analysis_plaintext, analysis_cyphertext))

# Once an R−1 round differential characteristic is discovered for a cipher of R rounds with
# a suitably large enough probability, it is conceivable to attack the cipher by recovering
# bits from the last subkey. In the case of our example cipher, it is possible to extract bits
# from subkey K5. The process followed involves partially decrypting the last round of the
# cipher and examining the input to the last round to determine if a right pair has probably
# occurred. We shall refer to the subkey bits following the last round at the output of S-
# boxes in the last round influenced by non-zero differences in the differential output as the
# target partial subkey. A partial decryption of the last round would involve, for all S-
# boxes in the last round influenced by non-zero differences in the differential, the
# exclusive-OR of the ciphertext with the target partial subkey bits and running the data
# backwards through the S-boxes, where all possible values for the target subkey bits
# would be tried.
# A partial decryption is executed for each pair of ciphertexts corresponding to the pairs of
# plaintexts used to generate the input difference ∆P for all possible target partial subkey
# values. A count is kept for each value of the target partial subkey value. The count is
# incremented when the difference for the input to the last round corresponds to the value
# expected from the differential characteristic. The partial subkey value which has the
# largest count is assumed to indicate the correct values of the subkey bits. This works
# because it is assumed that the correct partial subkey value will result in the difference to
# the last round being frequently as expected from the characterstic (i.e., the occurrence of
# a right pair) since the characteristic has a high probability of occurring. (When a wrong
# pair has occurred, even with the partial decryption with the correct subkey, the count for
# the correct subkey will likely not be incremented.) An incorrect subkey is assumed to
# result in a relatively random guess at the bits entering the S-boxes of the last round and as
# a result, the difference will be as expected from the characteristic with a very low
# probability.
# Considering the attack on our example cipher, the differential characteristic affects the
# inputs to S-boxes S42 and S44 in the last round. For each ciphertext pair, we would try all
# 256 values for [K5,5...K5,8, K5,13...K5,16]. For each partial subkey value, we would
# increment the count whenever the input difference to the final round determined by the
# partial decryption is the same as (6), where we determine the value of [∆U4,5... ∆U4,8,
# ∆U4,13... ∆U4,16] by running the data backwards through the partial subkey and S-boxes
# S24 and S44. For each partial subkey value, the count represents the number of occurrences
# of differences that are consistent with right pairs (assuming that the partial subkey is the
# correct value). The count that is the largest is taken to be the correct value since we
# assume that we are observing the high probability occurrence of the right pair.
