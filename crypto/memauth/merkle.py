"""Ordered Merkle tree using PDF p4's leaf/node domain separation."""
from dataclasses import dataclass
from typing import Callable


class UndefinedPaperRule(ValueError):
    """An abstract paper parameter or undefined boundary needs explicit selection."""


@dataclass(frozen=True)
class Parameters:
    hash_bytes: Callable[[bytes], bytes]
    encode_leaf: Callable[[object], bytes]
    digest_size: int
    odd_policy: str | None = None

    def __post_init__(self):
        if not callable(self.hash_bytes) or not callable(self.encode_leaf):
            raise TypeError('Hash and leaf encoding functions must be supplied')
        if type(self.digest_size) is not int or self.digest_size < 1:
            raise ValueError('Invalid digest size')
        if self.odd_policy not in (None, 'duplicate-last'):
            raise ValueError('Unknown odd-node policy')

    def digest(self, data):
        result = self.hash_bytes(data)
        if type(result) is not bytes or len(result) != self.digest_size:
            raise ValueError('Hash output does not match declared digest size')
        return result


def leaf_hash(value, parameters: Parameters) -> bytes:
    encoded = parameters.encode_leaf(value)
    if type(encoded) is not bytes:
        raise TypeError('Leaf encoding must return bytes')
    return parameters.digest(b'\x00' + encoded)


def node_hash(left: bytes, right: bytes, parameters: Parameters) -> bytes:
    if (type(left) is not bytes or type(right) is not bytes or
            len(left) != parameters.digest_size or len(right) != parameters.digest_size):
        raise ValueError('Merkle children have incorrect digest size')
    return parameters.digest(b'\x01' + left + right)


@dataclass(frozen=True)
class InclusionProof:
    index: int
    leaf_count: int
    siblings: tuple[tuple[str, bytes], ...]


class MerkleTree:
    def __init__(self, leaves, *, parameters: Parameters | None = None):
        if parameters is None:
            raise UndefinedPaperRule('Paper does not specify concrete H or leaf encoding')
        if type(leaves) not in (list, tuple) or not leaves:
            raise ValueError('Merkle tree requires a nonempty ordered leaf sequence')
        self.leaf_count = len(leaves)
        self.parameters = parameters
        level = tuple(leaf_hash(value, parameters) for value in leaves)
        levels = [level]
        while len(level) > 1:
            if len(level) % 2 and parameters.odd_policy is None:
                raise UndefinedPaperRule('Paper does not define odd-width Merkle levels')
            next_level = []
            for i in range(0, len(level), 2):
                right = level[i + 1] if i + 1 < len(level) else level[i]
                next_level.append(node_hash(level[i], right, parameters))
            level = tuple(next_level)
            levels.append(level)
        self._levels = tuple(levels)
        self.root = levels[-1][0]

    def inclusion_proof(self, index: int) -> InclusionProof:
        if type(index) is not int or not 0 <= index < self.leaf_count:
            raise IndexError('Merkle leaf index out of range')
        siblings, position = [], index
        for level in self._levels[:-1]:
            if position % 2:
                siblings.append(('left', level[position - 1]))
            else:
                siblings.append(('right', level[position + 1] if position + 1 < len(level) else level[position]))
            position //= 2
        return InclusionProof(index, self.leaf_count, tuple(siblings))

    @staticmethod
    def verify(value, proof: InclusionProof, root: bytes, *, parameters: Parameters | None = None) -> bool:
        if parameters is None:
            raise UndefinedPaperRule('Paper does not specify concrete H or leaf encoding')
        if (not isinstance(proof, InclusionProof) or type(proof.index) is not int or
                type(proof.leaf_count) is not int or proof.leaf_count < 1 or
                not 0 <= proof.index < proof.leaf_count or type(root) is not bytes or
                len(root) != parameters.digest_size):
            return False
        expected_depth, n = 0, proof.leaf_count
        while n > 1:
            if n % 2 and parameters.odd_policy is None:
                raise UndefinedPaperRule('Paper does not define odd-width Merkle levels')
            expected_depth += 1
            n = (n + 1) // 2
        if type(proof.siblings) not in (tuple, list) or len(proof.siblings) != expected_depth:
            return False
        current, position, width = leaf_hash(value, parameters), proof.index, proof.leaf_count
        for entry in proof.siblings:
            if type(entry) not in (tuple, list) or len(entry) != 2:
                return False
            side, sibling = entry
            if type(sibling) is not bytes or len(sibling) != parameters.digest_size:
                return False
            if side == 'left' and position % 2 == 1:
                current = node_hash(sibling, current, parameters)
            elif side == 'right' and position % 2 == 0:
                if position + 1 >= width and sibling != current:
                    return False
                current = node_hash(current, sibling, parameters)
            else:
                return False
            position //= 2
            width = (width + 1) // 2
        return current == root
