# shellforge/rng.py
"""Seeded randomness, and nothing that is not seeded.

THE WHOLE POINT IS THAT A CASE IS A FUNCTION OF ITS SEED. Same seed, same
bytes -- otherwise a failing score cannot be reproduced, and a test that
cannot be reproduced is a rumour.

That rules out `random` at module level, `time.time()`, `uuid4()`, dict
iteration over anything built from a set, and `os.urandom`. Everything that
needs a number asks a `Rng` for it.

SUB-STREAMS. `Rng.derive("logs")` returns an independent generator seeded from
the parent seed and a label. Without that, adding one file to the webroot
shifts every subsequent draw and the access log changes too -- which makes
diffing two runs useless for finding out what a change actually did.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta


class Rng:
    """A named, reproducible random stream."""

    def __init__(self, seed: int, label: str = "root"):
        self.seed = seed
        self.label = label
        # The label goes through a hash rather than into `Random(seed + label)`
        # so that "logs" and "logs2" are not neighbours in the seed space.
        digest = hashlib.sha256(f"{seed}:{label}".encode()).digest()
        self._r = random.Random(int.from_bytes(digest[:8], "big"))

    def derive(self, label: str) -> "Rng":
        return Rng(self.seed, f"{self.label}/{label}")

    # --- primitives ---------------------------------------------------------

    def choice(self, seq):
        return self._r.choice(list(seq))

    def sample(self, seq, k):
        seq = list(seq)
        return self._r.sample(seq, min(k, len(seq)))

    def shuffled(self, seq):
        out = list(seq)
        self._r.shuffle(out)
        return out

    def randint(self, a, b):
        return self._r.randint(a, b)

    def chance(self, p: float) -> bool:
        return self._r.random() < p

    def weighted(self, pairs):
        """pairs = [(value, weight), ...]"""
        values = [v for v, _ in pairs]
        weights = [w for _, w in pairs]
        return self._r.choices(values, weights=weights, k=1)[0]

    # --- domain helpers -----------------------------------------------------

    def hexs(self, n: int) -> str:
        return "".join(self._r.choice("0123456789abcdef") for _ in range(n))

    def token(self, n: int = 8) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(self._r.choice(alphabet) for _ in range(n))

    def ip(self, block: str) -> str:
        """An address out of a range reserved for exactly this.

        NEVER a real address. A test fixture that names a routable IP will
        eventually be pasted into a report, and then somebody gets accused of
        an intrusion because a generator needed a plausible number.

        `visitor`, `attacker` and `noise` come from the three documentation
        blocks of RFC 5737. Each is a /24, so each holds **254 addresses** --
        which is fine for the handful of roles a scenario has and is not fine
        for a crowd: asking for five hundred visitors out of a /24 quietly
        returns two hundred and fifty, and the case then claims a scale it
        does not have.

        `crowd` therefore uses 198.18.0.0/15, reserved by RFC 2544 for
        benchmarking and equally unroutable, which holds 131,072. It exists
        only so "more clients than the actor list can show" can be true.
        """
        if block == "crowd":
            return (f"198.{self.randint(18, 19)}."
                    f"{self.randint(0, 255)}.{self.randint(1, 254)}")
        base = {"visitor": "192.0.2", "attacker": "203.0.113",
                "noise": "198.51.100"}[block]
        return f"{base}.{self.randint(1, 254)}"

    def moment(self, day: datetime, start_hour=0, end_hour=23) -> datetime:
        """A time within one day, to the second."""
        hour = self.randint(start_hour, end_hour)
        return day.replace(hour=hour, minute=self.randint(0, 59),
                           second=self.randint(0, 59), microsecond=0)

    def jitter(self, when: datetime, seconds: int) -> datetime:
        return when + timedelta(seconds=self.randint(-seconds, seconds))
