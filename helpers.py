import random
from typing import Any, Callable, Iterator


class Block:
    # A block is a 16-bit number, represented as a tuple of four 4-bit numbers /
    # hexadecimal characters
    def __init__(self, block: tuple[int, ...]):
        assert len(block) == 4
        self.block = block

    def as_binary(self) -> tuple[int, ...]:
        # Convert the 16-bit number to a tuple of 16 bits
        return tuple([(self.block[i // 4] >> (3 - (i % 4))) & 1 for i in range(16)])

    def as_int(self) -> int:
        return int(str(self), 16)

    def get_bit(self, index: int) -> int:
        # Treats the four 4-bit numbers as a single 16-bit number and returns
        # the bit at the given index
        return (self.block[index // 4] >> (3 - (index % 4))) & 1

    def __iter__(self):
        # Iterate over 4-bit numbers / hexadecimal characters, not bits
        return iter(self.block)

    def __getitem__(self, index: int) -> int:
        # Get the 4-bit number at the given index, not the bit
        return self.block[index]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Block):
            return False
        return (
            self.block[0] == other.block[0]
            and self.block[1] == other.block[1]
            and self.block[2] == other.block[2]
            and self.block[3] == other.block[3]
        )

    def __or__(self, other: "Block") -> "Block":
        return Block(tuple([a | b for a, b in zip(self.block, other.block)]))

    def __and__(self, other: "Block") -> "Block":
        return Block(tuple([a & b for a, b in zip(self.block, other.block)]))

    def __xor__(self, other: "Block") -> "Block":
        return Block(tuple([a ^ b for a, b in zip(self.block, other.block)]))

    def __str__(self) -> str:
        return "".join([hex(i)[2:] for i in self.block])

    def __lt__(self, other: "Block") -> bool:
        return self.as_int() < other.as_int()

    def __gt__(self, other: "Block") -> bool:
        return self.as_int() > other.as_int()

    def __le__(self, other: "Block") -> bool:
        return self.as_int() <= other.as_int()

    def __ge__(self, other: "Block") -> bool:
        return self.as_int() >= other.as_int()

    def __ne__(self, other: "Block") -> bool:
        return self.as_int() != other.as_int()

    def __sub__(self, other: "Block") -> "Block":
        return Block(tuple([(a - b) % 0xF for a, b in zip(self.block, other.block)]))

    def __add__(self, other: "Block") -> "Block":
        return Block(tuple([(a + b) % 0xF for a, b in zip(self.block, other.block)]))

    def __hash__(self) -> int:
        return hash(self.as_int())


def bits_to_block(
    bits: (
        tuple[
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
        ]
        | tuple[int, ...]
    )
) -> Block:
    assert len(bits) == 16
    ints = []
    for i in range(0, 16, 4):
        ints.append(bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3] * 1)
    return Block(tuple(ints))


class SBox:
    keys = [
        0x0,
        0x1,
        0x2,
        0x3,
        0x4,
        0x5,
        0x6,
        0x7,
        0x8,
        0x9,
        0xA,
        0xB,
        0xC,
        0xD,
        0xE,
        0xF,
    ]

    def __init__(self, keys: list | None = None):
        if keys is not None:
            self.keys = keys

    def encrypt(self, plainnum: int) -> int:
        return self.keys[plainnum]

    def decrypt(self, cyphernum: int) -> int:
        return self.keys.index(cyphernum)

    def encrypt_block(self, plainblock: Block) -> Block:
        # Encrypt four 4-bit numbers at once
        block = []
        for num in plainblock:
            block.append(self.encrypt(num))
        return Block(tuple(block))

    def decrypt_block(self, cypherblock: Block) -> Block:
        # Decrypt four 4-bit numbers at once
        block = []
        for num in cypherblock:
            block.append(self.decrypt(num))
        return Block(tuple(block))

    def __str__(self) -> str:
        return " ".join([hex(i)[2:] for i in self.keys])


def _permute_index(index: int) -> int:
    # Simple bitwise shift permutation.
    #  0 -> 0, 1 -> 4,  2 -> 8,  3 -> 12, 4 -> 1, 5 -> 5,  6 -> 9,  7 -> 13, etc
    # Use this to permute the plaintext
    return (index % 4) * 4 + (index // 4)


def permute_block(block: Block) -> Block:
    return bits_to_block(tuple([block.get_bit(_permute_index(i)) for i in range(16)]))


class SPN:
    sbox: SBox  # Ordinarily, there would be multiple SBoxes
    round_keys: tuple[Block, ...]

    def __init__(self, sbox: SBox, round_keys: tuple[Block, ...]):
        self.sbox = sbox
        self.round_keys = round_keys

    def __str__(self) -> str:
        return f"SPN with SBox: {self.sbox} and round keys: {list(map(str, self.round_keys))}"

    def _cipher_round(
        self, num: Block, round_key: Block, forwards: bool, do_permute=True
    ) -> Block:
        result = num

        def _key_mixing(block: Block, key: Block) -> Block:
            return block ^ key

        def _substitution(block: Block, _: Block) -> Block:
            if forwards:
                return self.sbox.encrypt_block(block)
            else:
                return self.sbox.decrypt_block(block)

        def _permutation(block: Block, _: Block) -> Block:
            if do_permute:
                return permute_block(block)
            return block

        funcs = [_key_mixing, _substitution, _permutation]
        if not forwards:
            funcs = reversed(funcs)

        for func in funcs:
            result = func(result, round_key)

        return result

    def encrypt_block(self, plaintext: Block) -> Block:
        # 4 rounds of SPN
        result = plaintext
        for i in range(3):
            result = self._cipher_round(result, self.round_keys[i], True)
        # Final round without permutation
        result = self._cipher_round(result, self.round_keys[3], True, False)
        # Final key mixing
        result = result ^ self.round_keys[4]
        return result

    def encrypt(self, plaintext: list[Block]) -> list[Block]:
        return [self.encrypt_block(p) for p in plaintext]

    def decrypt_block(self, cyphertext: Block) -> Block:
        # 4 rounds of SPN
        result = cyphertext
        # Final key mixing
        result = result ^ self.round_keys[4]
        # Final round without permutation
        result = self._cipher_round(result, self.round_keys[3], False, False)
        for i in range(2, -1, -1):
            result = self._cipher_round(result, self.round_keys[i], False)
        return result

    def decrypt(self, cyphertext: list[Block]) -> list[Block]:
        return [self.decrypt_block(c) for c in cyphertext]


def random_4_bit() -> int:
    return random.randint(0, 15)


def random_block() -> Block:
    return Block(tuple([random_4_bit() for _ in range(4)]))


def generate_round_keys() -> tuple[Block, Block, Block, Block, Block]:
    # Randomly generate five 16-bit round keys (4 hex characters / a block)
    keys = []
    for i in range(5):
        keys.append(random_block())
    return tuple(keys)


def generate_plaintexts(n: int = 10000) -> list[Block]:
    # Generate 10,000 16-bit plaintexts
    plaintexts = []
    for i in range(n):
        plaintexts.append(random_block())
    return plaintexts


def generate_diffed_plaintexts(diff: Block, n: int = 10000) -> list[Block]:
    assert n % 2 == 0

    plaintexts = []
    for i in range(n // 2):
        b = random_block()
        b_prime = b ^ diff
        plaintexts.append(b)
        plaintexts.append(b_prime)

    return plaintexts


def write_secret_file(filename: str, data: str):
    with open("secret_" + filename, "w") as f:
        f.write(data)


def difference_distribution_table(sbox: SBox) -> list[list[int]]:
    # Compute the difference distribution table for the SBox. 16x16 table, rows
    # represent dX values, columns represent dY values. "Each element of the
    # table represents the number of occurrences of the corresponding output
    # difference dY value given the input difference dX."
    table = [[0 for _ in range(16)] for _ in range(16)]
    for x in range(16):
        for y in range(16):
            count = 0
            for i in range(16):
                if sbox.encrypt(i) ^ sbox.encrypt(i ^ x) == y:
                    count += 1
            table[x][y] = count

    with open("difference_distribution_table.txt", "w") as f:
        for row in table:
            f.write("\t".join(map(str, row)) + "\n")
    return table


def pretty_string_diff_table(diff_table: list[list[int]]) -> str:
    # Pretty string for the difference distribution table
    s = ""
    for row in diff_table:
        l = []
        for i in row:
            hex_char = hex(i)[2:]
            l.append(f"{hex_char.rjust(2)}")
        s += " ".join(l) + "\n"
    return s


def load_blocks(filename: str) -> list[Block]:
    # Assumes the file is a newline separated list of four 4-bit numbers each - one block per line.
    l = []
    with open(filename, "r") as f:
        for line in f:
            l.append(Block(tuple([int(c, 16) for c in line.strip().split()[0]])))
    return l


def biggest_in_rows(table: list[list[int]]) -> list[tuple[int, int]]:
    # Find the biggest value and the [first] index it occurs in each row
    return [(max(row), row.index(max(row))) for row in table]


def coordinate_of_max(table: list[list[int]], lt: int) -> tuple[int, int]:
    # Find the coordinate of the maximum value in the table
    # Use lt to find the maximum value less than lt
    max_val = 0
    max_coord = (0, 0)
    for i, row in enumerate(table):
        for j, val in enumerate(row):
            if val > max_val and val < lt:
                max_val = val
                max_coord = (i, j)
    return max_coord


def differential_characteristic_path(
    diff_table: list[list[int]], p: Block, rounds: int
) -> tuple[list[list[tuple[int, int]]], Block, float]:
    """
    Finds the best diffierential characteristic path for a given plaintext
    difference block p (\Delta P). Rounds is the number of rounds to consider,
    aka the amount of rounds in the SPN subtract one.

    Returns a 2d list of tuples, where each tuple is a pair of input and output
    differences for a round. As in, the top left tuple in the matrix is the
    input and output differences for the first sbox in the first round. Also
    returns the input to the final round and the probability of the path.
    """

    # Find the best output difference for each input difference
    best_diffs = biggest_in_rows(diff_table)

    path_matrix: list[list[tuple[int, int]]] = []
    cur = Block(p.block)
    result_probability = 1
    # For each round
    for round in range(rounds):
        path_matrix.append([])
        newCur = []
        for sbox_index in range(4):
            # For each sbox in the round, find the best input/output difference pair
            # for the sbox
            input_nibble = cur.block[sbox_index]
            output_nibble = best_diffs[input_nibble][1]
            path_matrix[round].append((input_nibble, output_nibble))
            newCur.append(output_nibble)
            if input_nibble != 0 or output_nibble != 0:
                # Update the probability of the path
                result_probability *= diff_table[input_nibble][output_nibble] / 16

        # Update the current block to the output of the round, then permute it
        cur = Block(tuple(newCur))
        cur = permute_block(cur)

    # Do a final encryption on the cur block to get the inputs to the last round
    last_round_inputs = cur

    return path_matrix, last_round_inputs, result_probability


def best_differential_characteristic(
    diff_table: list[list[int]],
    rounds: int,
    delta_ps: list[Block] | None = None,
    plaintexts: list[Block] | None = None,
    cyphertexts: list[Block] | None = None,
    affected_outputs: list[bool] | None = None,
    affected_count: int | None = None,
    epsilon: float | None = None,
) -> tuple[Block, Block, list[list[tuple[int, int]]], float] | None:
    """
    Find the best differential characteristic for the given difference
    distribution table and number of rounds. If plaintexts and cyphertexts are
    provided, only consider characteristics that have a good pair in the
    plaintexts and cyphertexts. If affected_outputs is provided, only consider
    characteristics that affect the given sboxes in the last round. If
    affected_count is provided, only consider characteristics that affect at
    least that many sboxes in the last round. If epsilon is provided, only
    consider characteristics with a probability greater than epsilon.
    Returns a tuple, where the tuple is the best input difference, the final
    round input difference, the path matrix, and the probability of the path.
    """
    count = 0
    total = 16**4
    best_probability = 0
    best_ret = None
    delta_p_to_use = delta_ps if delta_ps is not None else all_possible_blocks()
    for delta_p in delta_p_to_use:
        count += 1
        if delta_p == Block((0, 0, 0, 0)):
            continue
        path, input_to_final_round, probability = differential_characteristic_path(
            diff_table, delta_p, rounds
        )
        if epsilon is not None and probability <= epsilon:
            # Dont bother with these, we likely wont find a good pair in the collected plaintexts
            continue
        output_block = Block(tuple([path[-1][i][1] for i in range(4)]))
        if plaintexts is not None and cyphertexts is not None:
            good_pair = find_good_pair(delta_p, output_block, plaintexts, cyphertexts)
            if good_pair is None:
                continue
        output_boxes_affected_in_path = output_boxes_affected(input_to_final_round)
        if affected_outputs is not None:
            if not (
                (output_boxes_affected_in_path[0] and affected_outputs[0])
                or (output_boxes_affected_in_path[1] and affected_outputs[1])
                or (output_boxes_affected_in_path[2] and affected_outputs[2])
                or (output_boxes_affected_in_path[3] and affected_outputs[3])
            ):
                continue
        if affected_count is not None:
            if sum(output_boxes_affected_in_path) < affected_count:
                continue
        if probability > best_probability:
            best_probability = probability
            best_ret = (
                delta_p,
                input_to_final_round,
                path,
                probability,
            )
    return best_ret


def pretty_string_diff_characteristic_path(path: list[list[tuple[int, int]]]) -> str:
    s = ""
    rows = []
    for row in path:
        rows.append("  ".join([f"{hex(i[0])[2:]}->{hex(i[1])[2:]}" for i in row]))
    return "\n".join(rows)


def all_possible_blocks() -> Iterator[Block]:
    n = 0
    for i in range(16):
        for j in range(16):
            for k in range(16):
                for l in range(16):
                    yield Block((i, j, k, l))
                    n += 1


def find_difference(
    diff: Block, list_a: list[Block], list_b: list[Block]
) -> list[tuple[Block, Block]]:
    """
    Find the pairs in list_a and list_b that have a difference of diff
    """
    result = []
    for i in range(min(len(list_a), len(list_b))):
        if list_a[i] ^ list_b[i] == diff:
            result.append((list_a[i], list_b[i]))
    return result


def find_good_pair(
    input_diff: Block,
    expected_out: Block,
    plaintexts: list[Block],
    cyphertexts: list[Block],
) -> tuple[tuple[Block, Block], tuple[Block, Block]] | None:
    # Find a pair of plaintexts that have the given input difference and output
    # difference when encrypted

    plaintext_dict = {p: c for p, c in zip(plaintexts, cyphertexts)}

    for i, (p0, c0) in enumerate(plaintext_dict.items()):
        p1 = p0 ^ input_diff
        if p1 in plaintext_dict:
            c1 = plaintext_dict[p1]
            if c0 ^ c1 == expected_out:
                return (p0, c0), (p1, c1)


def find_all_good_pairs(
    input_diff: Block,
    expected_out_diff: Block,
    plaintexts: list[Block],
    cyphertexts: list[Block],
) -> list[tuple[tuple[Block, Block], tuple[Block, Block]]]:
    # Find all pair of plaintexts that have the given input difference and
    # output difference when encrypted
    plaintext_dict = {p: c for p, c in zip(plaintexts, cyphertexts)}
    good_pairs = []
    for i, (p0, c0) in enumerate(plaintext_dict.items()):
        p1 = p0 ^ input_diff
        if p1 in plaintext_dict:
            c1 = plaintext_dict[p1]
            if c0 ^ c1 == expected_out_diff:
                good_pairs.append(((p0, c0), (p1, c1)))
    return good_pairs


def find_pairs_with_diff(
    diff: Block,
    plaintexts: list[Block],
    cyphertexts: list[Block],
) -> list[tuple[tuple[Block, Block], tuple[Block, Block]]]:
    # Find all pairs of plaintexts that have the given difference
    plaintext_dict = {p: c for p, c in zip(plaintexts, cyphertexts)}
    good_pairs = []
    for i, (p0, c0) in enumerate(plaintext_dict.items()):
        p1 = p0 ^ diff
        if p1 in plaintext_dict:
            c1 = plaintext_dict[p1]
            good_pairs.append(((p0, c0), (p1, c1)))
    return good_pairs


def output_boxes_affected(final_round_input: Block) -> list[bool]:
    # Find which sboxes are affected in the last round of the path
    l = []
    for i in range(4):
        l.append(final_round_input.block[i] != 0)
    return l


def generate_partial_subkeys(
    box_one: bool, box_two: bool, box_three: bool, box_four: bool
) -> list[Block]:
    """Generates all the partial subkeys that affect the given sboxes.
    There is definitely a faster way to do this
    """
    psk_set = set()
    for i in range(16):
        i_num = i if box_one else 0
        for j in range(16):
            j_num = j if box_two else 0
            for k in range(16):
                k_num = k if box_three else 0
                for l in range(16):
                    l_num = l if box_four else 0
                    psk_set.add(Block((i_num, j_num, k_num, l_num)))
    return list(psk_set)


def side_by_side(strings: list[str], size: int = 20, space: int = 2) -> str:
    strings = list(strings)
    result = []

    while any(strings):
        line = []

        for i, s in enumerate(strings):
            buf = s[:size]

            try:
                n = buf.index("\n")
                line.append(buf[:n].ljust(size))
                strings[i] = s[n + 1 :]
            except ValueError:
                line.append(buf.ljust(size))
                strings[i] = s[size:]

        result.append((" " * space).join(line))

    return "\n".join(result)


def characteristic_string(
    title: str, c: tuple[Block, Block, list[list[tuple[int, int]]], float] | None
):
    if c is None:
        return f"{title}:\nNo characteristic found."
    best_input_diff, best_input_diff_final_round, best_path_matrix, best_probability = c
    return f"{title}:\nProbability: {best_probability:.2%}\nBest input difference: {best_input_diff}\nFinal round input difference: {best_input_diff_final_round}\n{pretty_string_diff_characteristic_path(best_path_matrix)}"
