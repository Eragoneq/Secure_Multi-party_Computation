from decimal import Decimal, getcontext
from random import randrange, getrandbits, randint


def is_prime(n: int) -> bool:
    """Returns `true` if and only if [n] is (very likely) a prime number (using the Miller-Rabin primality test)."""

    assert n >= 0

    if n in [0, 1, 4, 6, 8, 9]:
        return False
    if n in [2, 3, 5, 7]:
        return True

    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert 2 ** s * d == n - 1

    def trial_composite(c: int) -> bool:
        if pow(c, d, n) == 1:
            return False
        for j in range(s):
            if pow(c, 2 ** j * d, n) == n - 1:
                return False
        return True

    for i in range(8):
        a = randrange(2, n)
        if trial_composite(a):
            return False

    return True


def get_big_prime(bits: int) -> int:
    """Returns a random prime of [bits] long."""

    while True:
        prime = getrandbits(bits)
        if prime.bit_length() < bits:
            continue
        if is_prime(prime):
            break

    return prime


def get_random_invertible(low: int, high: int, mod: int) -> int:
    """Returns a random number between [low] (inclusive) and [high] (exclusive) that is multiplicatively invertible
    under modulo [mod]."""

    # min inclusive, max exclusive
    while True:
        candidate = randint(low, high)
        try:
            pow(candidate, -1, mod)
            return candidate
        except ValueError:
            pass


def dec2int(decimal: Decimal) -> int:
    """Losslessly encodes [decimal] as an [int]."""

    return int(decimal.scaleb(getcontext().prec))


def int2dec(integer: int) -> Decimal:
    """Losslessly decodes [integer] back into a [Decimal]."""

    return Decimal(integer).scaleb(-getcontext().prec)


def calculate_poly(f: list[int], x: int) -> int:
    """Calculates the polynomial f(x)."""
    return sum([f[i] * x ** i for i in range(len(f))])
