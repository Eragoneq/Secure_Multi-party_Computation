from __future__ import annotations

import functools
import math
import random
import statistics
from decimal import *
from random import randrange, sample
from typing import List, Tuple

import helper
from paillier import PublicKey, Paillier, PrivateKey


class Server:
    """A server interested in learning a machine learning model over private data using federated learning."""

    pk: PublicKey
    model: Decimal

    def __init__(self, pk: PublicKey):
        """Constructs a new server with knowledge of threshold Paillier public key [pk]."""

        self.pk = pk
        self.model = Decimal(0)

    def run_round(self, clients: List[Client]) -> None:
        """
        Runs a single round of federated learning with [clients].

        During a round, the server sends the model to each client, each client locally performs the calculation
        learning_rate * client_model + (1 - learning_rate) * server_model (note: the client does not change the
        client_model), and the server finds the average of the outputs of these calculations using a privacy-preserving
        summation.
        """

        # Each client performs a bit of training
        aggregates = [client.train_model(self.model) for client in clients]

        # Server aggregates the results
        aggregate = functools.reduce(lambda x, y: (x * y) % (self.pk.n**2), aggregates)

        # Ask each client to partially decrypt the aggregate
        partial_decryptions = dict([client.decrypt_aggregate(aggregate) for client in random.sample(clients, self.pk.t)])

        # Server combines the partial decryptions
        decrypted_sum = Paillier.combine_parts(self.pk, partial_decryptions)
        avg = helper.int2dec(decrypted_sum) / len(clients)

        # Server updates the model
        self.model = avg



class Client:
    """A client with private data who is prepared to participate in federated learning."""

    sk: PrivateKey
    learning_rate: Decimal
    model: Decimal

    def __init__(self, sk: PrivateKey, learning_rate: Decimal, model: Decimal):
        """
        Constructs a new client.

        Args:
            sk: a single threshold Paillier secret key
            learning_rate: the rate at which the server's model should move towards that of this client
            model: the client's private model
        """

        self.sk = sk
        self.learning_rate = learning_rate
        self.model = model

    def train_model(self, server_model: Decimal) -> int:
        """
        Given the [server_model], performs a bit of training, and returns the encrypted model.

        learning_rate * client_model + (1 - learning_rate) * server_model
        """

        return self.sk.pk.encrypt(
            helper.dec2int(self.learning_rate * self.model + (1 - self.learning_rate) * server_model))

    def decrypt_aggregate(self, aggregate: int) -> Tuple[int, int]:
        """(Partially) decrypts the [aggregate], returning both the [SecretKey#idx] and the partial decryption."""

        return self.sk.idx, self.sk.partial_decrypt(aggregate)


def main() -> None:
    # Parameters
    kappa: int = 256
    t: int = 3
    ell: int = 5
    rounds: int = 100
    learning_rate: Decimal = Decimal(0.3)

    # Setup
    pk, sks = Paillier.generate_keys(kappa, t, ell)  # TTP
    server = Server(pk)
    clients = [Client(sk, learning_rate, Decimal(randrange(1000))) for sk in sks.values()]
    real_mean = statistics.fmean([client.model for client in clients])

    # Run protocol
    for i in range(rounds):
        server.run_round(clients)
        print(f"Round {i + 1}: {server.model}")

    # Evaluate
    print(f"Modeled mean: {server.model}")
    print(f"Real mean:    {real_mean}")
    print(f"Close enough: {math.isclose(server.model, real_mean)}")


if __name__ == "__main__":
    main()
