import random

import helper


class Params:
    """Common parameters for the secret sharing scheme."""

    modulo: int
    generator: int

    def __init__(self, kappa: int):
        """Constructs a new set of parameters."""

        print("Generating params...")
        self.generator = 4
        while True:
            p = helper.get_big_prime(kappa)
            if helper.is_prime((p - 1) // 2):
                self.modulo = p
                break

        assert self.modulo.bit_length() == kappa
        print("Generated params!!!")

class PublicKey:
    """Public key for the secret sharing scheme."""

    params: Params
    idx: int
    value: int

    def __init__(self, params: Params, idx: int, value: int):
        """Constructs a new public key using the given [params], identifier [idx], and `g^e` [value]."""

        self.params = params
        self.idx = idx
        self.value = value


class PrivateKey:
    """Private key for the secret sharing scheme."""

    pk: PublicKey
    exponent: int

    def __init__(self, params: Params, idx: int):
        """Constructs a new public key with [params] and identifier [idx]."""

        self.exponent = random.randint(1, params.modulo - 1)
        self.pk = PublicKey(params, idx, pow(params.generator, self.exponent, params.modulo))

    def agree(self, pk: PublicKey) -> int:
        """Performs key agreement between this private key and [pk], negating the output depending on the relative order
        of the respective identifiers."""

        if self.pk.idx > pk.idx:
            return pow(pk.value, self.exponent, self.pk.params.modulo)
        else:
            return -pow(pk.value, self.exponent, self.pk.params.modulo)
