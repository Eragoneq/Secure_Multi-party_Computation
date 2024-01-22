import math
import time
import functools
import operator
from typing import Tuple, Dict
from helper import *


class PublicKey:
    """A threshold Paillier public key."""

    kappa: int
    n: int
    t: int
    ell: int
    g: int
    delta: int

    def __init__(self, kappa: int, n: int, t: int, ell: int):
        """
        Constructs a new threshold Paillier public key.

        Args:
            kappa: security parameter
            n: plaintext modulo
            t: decryption threshold
            ell: number of shares
        """

        self.kappa = kappa
        self.n = n
        self.n_sq = n ** 2
        self.t = t
        self.ell = ell
        self.g = n + 1
        self.delta = math.factorial(ell)

    def encrypt(self, m: int) -> int:
        """Encrypts [m] into a Paillier ciphertext."""

        r = get_random_invertible(1, self.n_sq, self.n_sq)
        c = (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return c


class PrivateKey:
    """A threshold Paillier private key."""

    pk: PublicKey
    idx: int
    share: int

    def __init__(self, pk: PublicKey, idx: int, share: int):
        """
        Constructs a new threshold Paillier private key.

        Args:
            pk: corresponding threshold Paillier public key
            idx: identifier to specify which share this is
            share: secret share for this private key
        """

        self.pk = pk
        self.idx = idx
        self.share = share

    def partial_decrypt(self, c: int) -> int:
        """Returns the partial decryption of [c]."""

        return pow(c, 2 * self.share * self.pk.delta, self.pk.n_sq) % self.pk.n_sq


class Paillier:
    @staticmethod
    def generate_keys(kappa: int, t: int, ell: int) -> Tuple[PublicKey, Dict[int, PrivateKey]]:
        """
        Generates the public key and private keys for threshold Paillier.

        Args:
            kappa: security parameter
            t: decryption threshold
            ell: number of shares

        Returns:
            the public key, and the indexed private keys
        """

        assert kappa > 0
        assert t <= ell

        print("Generating keys...")
        start_time = time.time()

        p_prime = 0
        q_prime = 0
        p = 0
        q = 0
        n = 0

        # Check p and q are prime
        while True:
            p_prime = get_big_prime(kappa // 2 - 1)
            p = 2 * p_prime + 1
            q_prime = get_big_prime(kappa // 2 - 1)
            q = 2 * q_prime + 1
            n = p * q
            if is_prime(p) and is_prime(q) and p != q and p_prime != q_prime and p != p_prime and q != q_prime and n.bit_length() == kappa:
                break

        assert n.bit_length() == kappa
        m = p_prime * q_prime

        d = m * pow(m, -1, n)

        assert d % m == 0
        assert d % n == 1

        f = [d] + [get_random_invertible(1, n * m - 1, n*m) for _ in range(t - 1)]

        pub_key = PublicKey(kappa, n, t, ell)
        priv_shares = {}
        for user in range(1, ell + 1):
            priv_key = PrivateKey(pub_key, user, calculate_poly(f, user))
            priv_shares[user] = priv_key

        print(f"Generated keys after {time.time() - start_time} seconds!")

        return pub_key, priv_shares

    @staticmethod
    def combine_parts(pk: PublicKey, parts: Dict[int, int]) -> int:
        """
        Combines the partial decryptions [parts] into a plaintext.

        Args:
            pk: public key
            parts: partial decryptions, indexed by which share decrypted it

        Returns:
            the plaintext
        """

        assert len(parts) >= pk.t

        c_prime = 1

        for i, share in parts.items():
            lam = functools.reduce(operator.mul, [-j for j in parts.keys() if j != i])
            lam *= (pk.delta // functools.reduce(operator.mul, [(i - j) for j in parts.keys() if j != i]))
            c_prime *= pow(share, 2 * lam, pk.n_sq)
            c_prime %= pk.n_sq

        return (((c_prime - 1) // pk.n) * pow(4 * (pk.delta ** 2), -1, pk.n)) % pk.n
