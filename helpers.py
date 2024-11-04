import random


class Block:
    # A block is a 16-bit number, represented as a tuple of four 4-bit numbers /
    # hexadecimal characters
    def __init__(self, block: tuple[int, ...]):
        assert len(block) == 4
        self.block = block

    def get_bit(self, index: int) -> int:
        # Treats the four 4-bit numbers as a single 16-bit number and returns
        # the bit at the given index
        return (self.block[index // 4] >> (3 - (index % 4))) & 1

    def __iter__(self):
        # Iterate over 4-bit numbers / hexadecimal characters, not bits
        return iter(self.block)

    def __str__(self) -> str:
        return "".join([hex(i)[2:] for i in self.block])


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


def mix_blocks(block1: Block, block2: Block) -> Block:
    return Block(tuple([a ^ b for a, b in zip(block1, block2)]))


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

    def shuffle(self):
        random.shuffle(self.keys)

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

    def _cipher_round(
        self, num: Block, round_key: Block, forwards: bool, do_permute=True
    ) -> Block:
        result = num

        def _key_mixing(block: Block, key: Block) -> Block:
            return mix_blocks(block, key)

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
        result = mix_blocks(result, self.round_keys[4])
        return result

    def encrypt(self, plaintext: list[Block]) -> list[Block]:
        return [self.encrypt_block(p) for p in plaintext]

    def decrypt_block(self, cyphertext: Block) -> Block:
        # 4 rounds of SPN
        result = cyphertext
        # Final key mixing
        result = mix_blocks(result, self.round_keys[4])
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


def generate_plaintexts() -> list[Block]:
    # Generate 10,000 16-bit plaintexts
    plaintexts = []
    for i in range(10000):
        plaintexts.append(random_block())
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
    # Pretty print the difference distribution table
    s = ""
    for row in diff_table:
        s += " ".join([hex(i)[2:] for i in row]) + "\n"
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


def differential_characteristic_path(
    sbox: SBox, p: Block, rounds: int
) -> tuple[list[list[tuple[int, int]]], float]:
    """
    Finds the best diffierential characteristic path for a given plaintext
    difference block p (\Delta P).

    Returns a 2d list of tuples, where each tuple is a pair of input and output
    differences for a round. As in, the top left tuple in the matrix is the
    input and output differences for the first sbox in the first round
    """

    # Step 1: Compute the difference distribution table for the S-Box
    diff_table = difference_distribution_table(sbox)

    # Step 2: Compute the best difference characteristic for the S-Box
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
            if input_nibble != 0 and output_nibble != 0:
                # Update the probability of the path
                result_probability *= diff_table[input_nibble][output_nibble] / 16

        # Update the current block to the output of the round, then permute it
        cur = Block(tuple(newCur))
        cur = permute_block(cur)

    return path_matrix, result_probability


def pretty_string_diff_characteristic_path(path: list[list[tuple[int, int]]]) -> str:
    s = ""
    for row in path:
        s += "  ".join([f"{hex(i[0])[2:]}->{hex(i[1])[2:]}" for i in row]) + "\n"
    return s
