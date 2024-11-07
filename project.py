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
best_input_diff, best_output_diff = coordinate_of_max(
    diff_table, 16
)  # 16 will always appear in the top left
print(f"Best input difference: {hex(best_input_diff)}")
print(f"Best output difference: {hex(best_output_diff)}")
best_delta_ps = [
    Block((0, 0, 0, best_input_diff)),
    Block((0, 0, best_input_diff, 0)),
    Block((0, best_input_diff, 0, 0)),
    Block((best_input_diff, 0, 0, 0)),
]  # Not sure how exactly delta p is found, but it seems that it can go in any one single slot of the block

bs = best_differential_characteristic(
    diff_table,
    3,
)
bdps = best_differential_characteristic(
    diff_table,
    3,
    best_delta_ps,
)

bac = best_differential_characteristic(
    diff_table,
    3,
    affected_count=2,
)

print(
    side_by_side(
        [
            characteristic_string("Best Characteristic - Overall", bs),
            characteristic_string(
                f"Best Characteristic - '{best_input_diff}' in ΔP", bdps
            ),
            characteristic_string("Best Characteristic - 2 S-Boxes affected", bac),
        ],
        size=42,
    )
)

key_1, key_2, key_3, key_4, key_5 = generate_round_keys()

spn = SPN(sbox, (key_1, key_2, key_3, key_4, key_5))
assert bac is not None
(
    dp,
    best_output_diff_final_round,
    best_path,
    best_probability,
) = bac  # Using the best characteristic with 2 affected sboxes, to ensure that a whole byte can be found

plaintext = generate_diffed_plaintexts(dp)
ciphertext = spn.encrypt(plaintext)

write_secret_file("keys.txt", f"{key_1}\n{key_2}\n{key_3}\n{key_4}\n{key_5}")
write_secret_file("plaintexts.txt", "\n".join([str(p) for p in plaintext]))
write_secret_file("ciphertexts.txt", "\n".join([str(c) for c in ciphertext]))


# ------------------------------------------------------------------------------ Differential cryptanalysis

analysis_plaintext = load_blocks("analysis_plaintexts.txt")
analysis_cyphertext = load_blocks("analysis_ciphertexts.txt")


def find_last_key_byte(
    sbox: SBox,
    plaintexts: list[Block],
    cyphertexts: list[Block],
) -> Block:
    """
    Find a byte of the last key using differential cryptanalysis.
    """

    print("-" * 30 + f"Attacking S-Box ({sbox})" + "-" * 30)

    # Step 1: Compute the difference distribution table for the S-Box
    print("- Computing difference distribution table...")
    diff_table = difference_distribution_table(sbox)

    # Step 2: Compute the best difference characteristic for the S-Box
    print("- Computing best differential characteristic...")
    best_characteristic = best_differential_characteristic(
        diff_table,
        3,
        affected_count=2,
    )

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

    # Step 3: Compute the probability of each partial subkey
    # Only need to check subkeys based on the sboxes that are affected in the last row of the path
    # Only try subkeys that affect the sboxes in the path. ie if the path includes the second and fourth sboxes, only try subkeys in range 0000 0000 0000 0001 to 0000 1111 0000 1111
    boxes_affected = output_boxes_affected(final_round_input_diff)
    subkeys_to_try = generate_partial_subkeys(
        boxes_affected[0], boxes_affected[1], boxes_affected[2], boxes_affected[3]
    )
    # For each cyphertext pair, try each subkey and see if the partial decryption matches the path
    print("- Computing subkey probabilities...")
    subkey_probabilities: dict[Block, int] = {}
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


print(
    f"Last key will be: '{"".join([hex(x)[2:] if x != 0 else "_" for x in find_last_key_byte(sbox, analysis_plaintext, analysis_cyphertext)])}'"
)
