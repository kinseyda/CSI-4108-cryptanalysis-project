import random


class Block:
    # A block is a 16-bit number, represented as a tuple of four 4-bit numbers /
    # hexadecimal characters
    def __init__(self, block: tuple[int, ...]):
        assert len(block) == 4
        self.block = block

    def get_bit(self, index: int) -> int:
        return (self.block[index // 4] >> (index % 4)) & 1

    def __iter__(self):
        # Iterate over 4-bit numbers / hexadecimal characters, not bits
        return iter(self.block)

    def __str__(self) -> str:
        return "".join([hex(i)[2:] for i in self.block])


def bits_to_block(
    bits: tuple[
        int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int
    ]
) -> Block:
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

    def __str__(self) -> str:
        return " ".join([hex(i)[2:] for i in self.keys])


def _permute_index(index: int) -> int:
    # Simple shift permutation
    # 1 -> 1, 5 -> 2, 9 -> 3, 13 -> 4, 2 -> 5, etc
    # Use this to permute the plaintext
    return (index % 4) * 4 + (index // 4)


def permute_block(block: Block) -> Block:
    permuted_bits = []
    for i in range(16):
        permuted_bits.append(block.get_bit(_permute_index(i)))
    return bits_to_block(tuple(permuted_bits))


class SPN:
    sbox: SBox  # Ordinarily, there would be multiple SBoxes
    round_keys: tuple[Block, ...]

    def __init__(self, sbox: SBox, round_keys: tuple[Block, ...]):
        self.sbox = sbox
        self.round_keys = round_keys

    def _cipher_round(
        self, plain_num: Block, round_key: Block, do_permute=True
    ) -> Block:
        # 1. Substitution
        # 2. Permutation
        # 3. Key mixing
        result = plain_num
        # Substitution
        result = self.sbox.encrypt_block(result)
        # Permuation
        if do_permute:
            result = permute_block(result)
        # Key mixing
        result = mix_blocks(result, round_key)
        return result

    def encrypt_block(self, plaintext: Block) -> Block:
        # 4 rounds of SPN
        result = plaintext
        for i in range(4):
            result = self._cipher_round(result, self.round_keys[i])
        # Final round without permutation
        result = self._cipher_round(result, self.round_keys[4], do_permute=False)
        return result

    def encrypt(self, plaintext: list[Block]) -> list[Block]:
        return [self.encrypt_block(p) for p in plaintext]


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
    return table


def best_difference_characteristic(
    sbox: SBox, rounds: int
) -> tuple[tuple[int, int, float], ...]:
    # Finds the best difference characteristic for the SBox (assumes the same
    # sbox for each round). A difference characteristic is "a sequence of input
    # and output differences to the rounds so that the output difference from
    # one round corresponds to the input difference for the next round."
    # Returns a tuple of `rounds` tuples (input difference, output difference, probability)

    # TODO May want to change method signature? idk
    return ((0, 0, 0.0),)


def pretty_string_diff_table(diff_table: list[list[int]]) -> str:
    # Pretty print the difference distribution table
    s = ""
    for row in diff_table:
        s += " ".join([hex(i)[2:] for i in row]) + "\n"
    return s
