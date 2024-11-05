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

key_1, key_2, key_3, key_4, key_5 = generate_round_keys()

spn = SPN(sbox, (key_1, key_2, key_3, key_4, key_5))

plaintext = generate_plaintexts()
ciphertext = spn.encrypt(plaintext)

print("Test encryption / decryption:")
print(f"Plaintext: {plaintext[0]}")
print(f"Ciphertext: {ciphertext[0]}")
print(f"Decrypted: {spn.decrypt(ciphertext)[0]}")

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

    # Step 1: Compute the difference distribution table for the S-Box
    print("Computing difference distribution table...")
    diff_table = difference_distribution_table(sbox)

    # Step 2: Compute the best difference characteristic for the S-Box
    print("Computing best differential characteristic...")
    best_characteristic = best_differential_characteristic(
        diff_table, 4, plaintexts, cyphertexts
    )

    if best_characteristic is None:
        print(
            "No characteristic with a good pair in the plaintexts / cyphertexts found."
        )
        return None

    (
        best_input_diff,
        final_round_input_diff,
        best_output_diff,
        best_path,
        best_probability,
    ) = best_characteristic

    good_pairs = find_all_good_pairs(
        best_input_diff, best_output_diff, plaintexts, cyphertexts
    )

    print(pretty_string_diff_characteristic_path(best_path))
    print(f"Best probability: {best_probability}")
    print(f"Number of good pairs: {len(good_pairs)}")
    print(f"Best input difference: {best_input_diff}")
    print(f"Final round input difference: {final_round_input_diff}")
    print(f"Best output difference: {best_output_diff}")

    # Step 3: Compute the probability of each partial subkey
    # Only need to check subkeys based on the sboxes that are affected in the last row of the path
    sbox_mask = [0 for _ in range(4)]
    for i in range(4):
        if best_path[-1][i][0] != 0 or best_path[-1][i][1] != 0:
            sbox_mask[i] = 0xF
        else:
            sbox_mask[i] = 0x0
    sbox_mask = Block(tuple(sbox_mask))
    subkeys_to_try: list[Block] = list(
        filter(lambda x: x & sbox_mask != Block((0, 0, 0, 0)), all_possible_blocks())
    )  # Only try subkeys that affect the sboxes in the path. ie if the path includes the second and fourth sboxes, only try subkeys in range 0000 0000 0000 0001 to 0000 1111 0000 1111

    # For each cyphertext pair, try each subkey and see if the partial decryption matches the path
    print("Computing subkey probabilities...")
    subkey_probabilities = {}
    for (p0, c0), (p1, c1) in good_pairs:
        for subkey in subkeys_to_try:
            partial_decrypt0 = Block(tuple(sbox.decrypt_block(c0 ^ subkey)))
            partial_decrypt1 = Block(tuple(sbox.decrypt_block(c1 ^ subkey)))
            if partial_decrypt0 ^ partial_decrypt1 == final_round_input_diff:
                if subkey in subkey_probabilities:
                    subkey_probabilities[subkey] += 1
                else:
                    subkey_probabilities[subkey] = 1

    # Print a table showing the probability of each partial subkey
    print("Top 10 subkey probabilities:")
    for subkey, probability in sorted(
        subkey_probabilities.items(), key=lambda x: x[1], reverse=True
    )[:10]:
        print(f"{subkey}: {probability}")
    best_subkey, best_subkey_probability = max(
        subkey_probabilities.items(), key=lambda x: x[1]
    )
    print(f"Best subkey: {best_subkey} with probability {best_subkey_probability}")
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
