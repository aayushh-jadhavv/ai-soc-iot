"""Immutable output masks and the registered seeded genetic operators."""

from dataclasses import dataclass
import math

import torch

WIDTHS = (64, 32)
MIN_CHANNELS = 4


def check_bits(layers):
    if len(layers) != 2 or any(len(bits) != n for bits, n in zip(layers, WIDTHS)):
        raise ValueError("Masks must have lengths 64 and 32")
    if any(type(bit) is not int or bit not in (0, 1) for bits in layers for bit in bits):
        raise ValueError("Mask bits must be binary integers")


@dataclass(frozen=True)
class Mask:
    conv1: tuple
    conv2: tuple

    def __post_init__(self):
        # Normalize lists so a frozen mask cannot contain mutable layers.
        object.__setattr__(self, "conv1", tuple(self.conv1))
        object.__setattr__(self, "conv2", tuple(self.conv2))
        check_bits(self.layers)
        if min(self.retained) < MIN_CHANNELS:
            raise ValueError("At least four retained channels per layer required")

    @property
    def layers(self):
        return (self.conv1, self.conv2)

    @property
    def retained(self):
        return tuple(sum(bits) for bits in self.layers)

    @property
    def code(self):
        return ":".join("".join(map(str, bits)) for bits in self.layers)

    @classmethod
    def decode(cls, code):
        parts = code.split(":")
        if len(parts) != 2 or any(bit not in "01" for part in parts for bit in part):
            raise ValueError("Invalid mask encoding")
        return cls(*(tuple(map(int, part)) for part in parts))


ALL_ONES = Mask((1,) * 64, (1,) * 32)


def repair(layers, rng):
    check_bits(layers)
    result = [list(bits) for bits in layers]
    for bits in result:
        deficit = max(0, MIN_CHANNELS - sum(bits))
        for index in rng.sample([i for i, bit in enumerate(bits) if not bit], deficit):
            bits[index] = 1
    return Mask(*result)


def initial_population(rng):
    return [ALL_ONES] + [repair([[int(rng.random() < .5) for _ in range(n)]
                                 for n in WIDTHS], rng) for _ in range(19)]


def crossover(first, second, rng):
    """One Bernoulli trial per pair; exchange tails in exactly one layer."""
    a, b = [list(x) for x in first.layers], [list(x) for x in second.layers]
    if rng.random() < .6:
        layer = rng.randrange(2)
        point = rng.randrange(1, WIDTHS[layer])
        a[layer][point:], b[layer][point:] = b[layer][point:], a[layer][point:]
    # Crossing can temporarily violate the minimum. Repair only after mutation.
    return a, b


def mutate_and_repair(layers, rng):
    return repair([[1 - bit if rng.random() < .05 else bit for bit in bits]
                   for bits in layers], rng)


def roulette(weights, rng):
    """Invalid weights are ineligible; all valid zero weights sample uniformly."""
    valid = [i for i, w in enumerate(weights) if w is not None and math.isfinite(w) and w >= 0]
    if not valid:
        raise ValueError("No valid parents for roulette selection")
    total = math.fsum(weights[i] for i in valid)
    if total == 0:
        return rng.choice(valid)
    target, cumulative = rng.random() * total, 0.0
    positive = [i for i in valid if weights[i] > 0]
    for index in positive:
        cumulative += weights[index]
        if target < cumulative:
            return index
    return positive[-1]  # Floating-point summation at the right endpoint.


@torch.inference_mode()
def masked_forward(model, x, mask):
    # Mask after ReLU/affine output: a removed channel's bias cannot leak onward.
    first = x.new_tensor(mask.conv1).reshape(1, 64, 1)
    second = x.new_tensor(mask.conv2).reshape(1, 32, 1)
    hidden = torch.relu(model.conv1(x)) * first
    hidden = torch.relu(model.conv2(hidden)) * second
    return model.output(hidden.mean(dim=2))


def retention_cost(mask):
    c1, c2 = mask.retained
    parameters = 49 * c1 + 3 * c1 * c2 + 2 * c2 + 1
    macs = 8 * 16 * c1 * 3 + 8 * c1 * c2 * 3 + c2
    return dict(retained_conv1=c1, retained_conv2=c2,
                retention=(c1 + c2) / 96, channel_sparsity=1 - (c1 + c2) / 96,
                potential_compact_parameters=parameters,
                potential_parameter_reduction=1 - parameters / 9345,
                potential_compact_macs=macs, potential_mac_reduction=1 - macs / 73760,
                evaluated_dense_parameters=9345, evaluated_dense_macs=73760)
