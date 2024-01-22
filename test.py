import helper
import random
from paillier import Paillier

def test() -> None:
    # Parameters
    kappa: int = 16
    t: int = 3
    ell: int = 5

    # Setup
    pk, sks = Paillier.generate_keys(kappa, t, ell)

    # Test
    # secret = helper.get_random_invertible(1, 10**4, pk.n)
    secret = 19484
    secret2 = 20000

    print(f"Secret: {secret}")

    # Encrypt
    enc = pk.encrypt(secret)
    enc2 = pk.encrypt(secret2)
    print(f"Encrypted: {enc}")
    print(f"Encrypted2: {enc2}")

    result = enc * enc2

    # Partial decrypt
    part = []
    for id, sk in random.sample(list(sks.items()), t):
        part.append((id, sk.partial_decrypt(result)))

    print("parts:", part)
    print("len(parts):", len(part))
    # Combine
    dec = Paillier.combine_parts(pk, dict(part))

    print("decrypted:", dec)

    assert dec == secret + secret2

if __name__ == "__main__":
    test()