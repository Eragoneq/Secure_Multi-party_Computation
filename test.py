import helper
from paillier import Paillier

def test() -> None:
    # Parameters
    kappa: int = 256
    t: int = 3
    ell: int = 5

    # Setup
    pk, sks = Paillier.generate_keys(kappa, t, ell)

    # Test
    secret = helper.get_random_invertible(1, 10000, pk.n)
    print(f"Secret: {secret}")

    # Encrypt
    enc = pk.encrypt(secret)

    # Partial decrypt
    part = []
    for id, sk in sks.items():
        if len(part) == t:
            break
        part.append((id, sk.partial_decrypt(enc)))

    # Combine
    dec = Paillier.combine_parts(pk, dict(part))

    print(dec)

    assert dec == secret

if __name__ == "__main__":
    test()