from __future__ import annotations

import random
import string

from attackcastle.scope.parser import parse_target_input


def _random_token(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + ".:-/_*[]?%@!$ "
    length = rng.randint(0, 40)
    return "".join(rng.choice(alphabet) for _ in range(length)).strip()


def test_parse_target_input_randomized_stability():
    rng = random.Random(20260310)
    separators = [",", "\n", ",\n", "\n,", "\n\n", ",,\n"]
    for _ in range(1000):
        token_count = rng.randint(0, 6)
        tokens = [_random_token(rng) for _index in range(token_count)]
        expected = [token for token in tokens if token]
        separator = rng.choice(separators)
        raw_input = separator.join(tokens)
        targets = parse_target_input(raw_input)
        assert len(targets) == len(expected)
        for target in targets:
            assert target.target_id.startswith("target_")
            assert target.value == target.value.strip()

