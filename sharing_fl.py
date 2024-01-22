from __future__ import annotations

import math
import statistics
from decimal import *
from random import randrange
from typing import List

import helper
from sharing import Params, PrivateKey, PublicKey


class Server:
    params: Params
    model: Decimal

    def __init__(self, params: Params):
        """Constructs a new server with knowledge of the scheme's public parameters."""

        self.params = params
        self.model = Decimal(0)


    def run_round(self, clients: List[Client]) -> None:
        """Runs a single round of federated learning with [clients]."""

        # Get key from each client
        pks = [client.send_key() for client in clients]

        # Distribute server model to each client with public keys
        client_models = [client.train_model(self.model, pks) for client in clients]

        # Aggregate client models
        self.model = helper.int2dec(sum(client_models) // len(clients))


class Client:
    """A client with private data who is prepared to participate in federated learning."""

    idx: int
    params: Params
    learning_rate: Decimal
    model: Decimal
    sk: PrivateKey

    def __init__(self, idx: int, params: Params, learning_rate: Decimal, model: Decimal):
        """
        Constructs a new client.

        Args:
            idx: the client's (unique) identifier
            params: the scheme's public parameters
            model: the client's private model
        """

        self.idx = idx
        self.params = params
        self.learning_rate = learning_rate
        self.model = model
        self.sk = PrivateKey(self.params, self.idx)

    def send_key(self) -> PublicKey:
        """
        Returns the client's public key.
        """

        # Return the most recent public key
        return self.sk.pk

    def train_model(self, server_model: Decimal, pks: List[PublicKey]) -> int:
        """
        Iterates the client's model towards the [server_model] and returns the updated model secret-shared with the
        clients identified in [pks].
        """

        noise = sum([self.sk.agree(pk) for pk in pks if pk.idx != self.idx])

        # Generate new keys after use
        self.sk = PrivateKey(self.params, self.idx)

        # Send updated model to server
        return helper.dec2int((self.learning_rate * self.model + (1 - self.learning_rate) * server_model)) + noise




def main() -> None:
    # Parameters
    params: params = Params(256)
    ell: int = 10
    rounds: int = 100
    learning_rate: Decimal = Decimal(0.3)

    # Construct
    server = Server(params)
    clients = [Client(i, params, learning_rate, Decimal(randrange(1000))) for i in range(ell)]
    real_mean = statistics.fmean([client.model for client in clients])

    # Run protocol
    for i in range(rounds):
        server.run_round(clients)
        print(f"Round {i + 1}: {server.model}")

    # Evaluate
    print(f"Modeled mean: {server.model}")
    print(f"Real mean:    {statistics.fmean([client.model for client in clients])}")
    print(f"Close enough: {math.isclose(server.model, real_mean)}")


if __name__ == "__main__":
    main()
