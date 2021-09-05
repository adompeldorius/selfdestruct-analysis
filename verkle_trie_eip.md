---
eip: XXXX
title: Verkle tree integration
author: Vitalik Buterin (@vbuterin), Dankrad Feist (@dankrad)
discussions-to: YYYY
status: Draft
type: Standards Track
category: Core
created: 2021-ZZ-WW
---

## Simple Summary

Introduce a new Verkle state tree alongside the existing hexary Patricia tree. After the hard fork, the Verkle tree stores all edits to state and a copy of all accessed state, and the hexary Patricia tree can no longer be modified. This is a first step in a multi-phase transition to Ethereum exclusively relying on Verkle trees to store execution state.

## Motivation

[Verkle trees](https://notes.ethereum.org/_N1mutVERDKtqGIEYc-Flw) solve the key problem standing in the way of Ethereum being stateless-client-friendly: witness sizes. A witness accessing an account in today's hexary Patricia tree is, in the average case, close to 3 kB, and in the worst case it may be three times larger. Assuming a worst case of 6000 accesses per block (15m gas / 2500 gas per access), this corresponds to a witness size of ~18 MB, which is too large to safely broadcast through a p2p network within a 12-second slot. Verkle trees reduce witness sizes to ~200 bytes per account in the average case, allowing stateless client witnesses to be acceptably small.

## Specification


### Verkle tree definition

We define a Verkle tree here by providing the function to compute the root commitment given a set of 32-byte keys and 32-byte values. Algorithms for updating and inserting values are up to the implementer; the only requirement is that the root commitment after the update must continue to match the value computed from this specification. We will then define an embedding that provides the 32-byte key at which any particular piece of state information (account headers, code, storage) should be stored.

```python
# Bandersnatch curve order
BANDERSNATCH_MODULUS = \
13108968793781547619861935127046491459309155893440570251786403306729687672801
# Bandersnatch Pedersen basis of length 256
PEDERSEN_BASIS = [....]
VERKLE_NODE_WIDTH = len(PEDERSEN_BASIS)

def group_to_field(point: G1Point) -> int:
    # Not collision resistant. Not random oracle. 
    # Binding for Pedersen commitments.
    assert isinstance(point, G1Point)
    if point == bandernatch.Z:
        return 0
    else:
        return int.from_bytes(serialize(point), 'little') % BANDERSNATCH_MODULUS
    
def compute_commitment_root(children: Sequence[int]) -> int:
    o = bandersnatch.Z
    for generator, child in zip(PEDERSEN_BASIS, children):
        o = bls.add(o, bls.mul(generator, child))
    return group_to_field(o)

def extension_and_suffix_tree(stem: bytes31, values: List[bytes32, 256]) -> int:
    sub_leaves = []
    for value in values:
        sub_leaves.extend([
            int.from_bytes(value[:16], 'little') + 2**128,
            int.from_bytes(value[16:], 'little')
        ])
    C1 = compute_commitment_root(sub_leaves[:256])
    C2 = compute_commitment_root(sub_leaves[256:])
    return compute_commitment_root([1, # Extension marker
                                    int.from_bytes(stem, "little"),
                                    group_to_field(C1),
                                    group_to_field(C2)] +
                                    [0] * 252)

def compute_main_tree_root(data: Dict[bytes32, int],
                           prefix: bytes) -> int:
    # Empty tree: 0
    if len(data) == 0:
        return 0
    # Single element: byte-pack [key, value]
    elif len(data) == 1:
        key, value = list(data.items())[0]
        return value
    else:
        sub_commitments = [
            compute_main_tree_root({
                    key: value for key, value in data.items() if
                    key[:len(prefix) + 1] == prefix + bytes([i])
                }, prefix + bytes([i]))
            for i in range(VERKLE_NODE_WIDTH)
        ]
        return compute_commitment_root(sub_commitments)
        
def compute_verkle_root(data: Dict[bytes32, bytes32]) -> int:
    stems = set(key[:-1] for key in data.keys())
    data_as_stems = {}
    for stem in stems:
        commitment_data = [0] * 256
        for i in range(VERKLE_NODE_WIDTH):
            if stem + bytes([i]) in data:
                commitment_data[i] = data[stem + bytes([i])
        data_as_stems[stem] = extension_and_suffix_tree(stem, commitment_data)
    return compute_main_tree_root(data_as_stems, b'')
```

Note that a value of zero is not the same thing as a position being empty; a position being empty is represented as 0 in the bottom layer commitment, but a position being zero is represented as `pedersen_leaf(stem, b"")` in the commitment. This distinction between zero and empty is not a property of the existing Patricia tree, but it is a property of the proposed Verkle tree.

In the rest of this document, saving or reading a number at some position in the Verkle tree will mean saving or reading the 32-byte little-endian encoding of that number.

### Illustration

This is an illustration of the tree structure.
![](https://storage.googleapis.com/ethereum-hackmd/upload_2eea7f262d0e6a38fa048c6194df24ea.png)

### Tree embedding

Instead of a two-layer structure as in the Patricia tree, in the Verkle tree we will embed all information into a single `key: value` tree. This section specifies which tree keys store the information (account header data, code, storage) in the state.

| Parameter | Value |
| - | - |
| `VERSION_LEAF_KEY` | 0 |
| `BALANCE_LEAF_KEY` | 1 |
| `NONCE_LEAF_KEY` | 2 |
| `CODE_KECCAK_LEAF_KEY` | 3 |
| `CODE_SIZE_LEAF_KEY` | 4 |
| `HEADER_STORAGE_OFFSET` | 64 |
| `CODE_OFFSET` | 128 |
| `VERKLE_NODE_WIDTH` | 256 |
| `MAIN_STORAGE_OFFSET` | 256**31 |

_It's a required invariant that `VERKLE_NODE_WIDTH > CODE_OFFSET > HEADER_STORAGE_OFFSET` and that `HEADER_STORAGE_OFFSET` is greater than the leaf keys. Additionally, `MAIN_STORAGE_OFFSET` must be a power of `VERKLE_NODE_WIDTH`._

Note that addresses are always passed around as an `Address32`. To convert existing addresses to `Address32`, prepend with 12 zero bytes:

```python
def old_style_address_to_address32(address: Address) -> Address32:
    return b'\x00' * 12 + address
```

#### Header values

These are the positions in the tree at which block header fields of an account are stored.

```python
def pedersen_hash(inp: bytes) -> bytes32:
    assert len(inp) <= 255 * 16
    # Interpret input as list of integers in 0..255
    ext_input = inp + b"\0" * (255 * 16 - len(inp))
    ints = [2 + 256 * len(inp)] + \
           [int.from_bytes(ext_input[16 * i:16 * (i + 1)]) for i in range(255)]
    return compute_commitment_root(ints).to_bytes(32, 'little')

def get_tree_key(address: Address32, tree_index: int, sub_index: int):
    # Asssumes VERKLE_NODE_WIDTH = 256
    return (
        pedersen_hash(address + tree_index.to_bytes(32, 'little'))[:31] +
        bytes([sub_index])
    )
    
def get_tree_key_for_version(address: Address32):
    return get_tree_key(address, 0, VERSION_LEAF_KEY)
    
def get_tree_key_for_balance(address: Address32):
    return get_tree_key(address, 0, BALANCE_LEAF_KEY)
    
def get_tree_key_for_nonce(address: Address32):
    return get_tree_key(address, 0, NONCE_LEAF_KEY)

# Backwards compatibility for EXTCODEHASH    
def get_tree_key_for_code_keccak(address: Address32):
    return get_tree_key(address, 0, CODE_KECCAK_LEAF_KEY)
    
# Backwards compatibility for EXTCODESIZE
def get_tree_key_for_code_size(address: Address32):
    return get_tree_key(address, 0, CODE_SIZE_LEAF_KEY)
```

When any account header field is set, the `version` is also set to zero. The `code_keccak` and `code_size` fields are set upon contract creation.

### Code

```python
def get_tree_key_for_code_chunk(address: Address32, chunk_id: int):
    return get_tree_key(
        address,
        (CODE_OFFSET + chunk_id) // VERKLE_NODE_WIDTH,
        (CODE_OFFSET + chunk_id)  % VERKLE_NODE_WIDTH
    )
```

Chunk `i` stores a 32 byte value, where bytes 1...31 are bytes `i*31...(i+1)*31 - 1` of the code (ie. the i’th 31-byte slice of it), and byte 0 is the number of leading bytes that are part of PUSHDATA (eg. if part of the code is `...PUSH4 99 98 | 97 96 PUSH1 128 MSTORE...` where `|` is the position where a new chunk begins, then the encoding of the latter chunk would begin `2 97 96 PUSH1 128 MSTORE` to reflect that the first 2 bytes are PUSHDATA).

For precision, here is an implementation of code chunkification:

```python
PUSH_OFFSET = 95
PUSH1 = PUSH_OFFSET + 1
PUSH32 = PUSH_OFFSET + 32

def chunkify_code(code: bytes) -> Sequence[bytes32]:
    # Pad to multiple of 31 bytes
    if len(code) % 31 != 0:
        code += b'\x00' * (31 - (len(code) % 31))
    # Figure out how much pushdata there is after+including each byte
    bytes_to_exec_data = [0] * len(code)
    pos = 0
    while pos < len(code):
        if PUSH1 <= code[pos] <= PUSH32:
            pushdata_bytes = code[pos] - PUSH_OFFSET
        else:
            pushdata_bytes = 0
        pos += 1
        for x in range(pushdata_bytes):
            bytes_to_exec_data[pos + x] = pushdata_bytes - x
        pos += pushdata_bytes
    # Output chunks
    return [
        bytes([min(bytes_to_exec_data[pos], 31)]) + code[pos: pos+31]
        for pos in range(0, len(code), 31)
    ]
```

### Storage

```python
def get_tree_key_for_storage_slot(address: Address32, storage_key: int):
    if storage_key < (CODE_OFFSET - HEADER_STORAGE_OFFSET):
        pos = HEADER_STORAGE_OFFSET + storage_key
    else:
        pos = MAIN_STORAGE_OFFSET + storage_key
    return get_tree_key(
        address,
        pos // VERKLE_NODE_WIDTH,
        pos % VERKLE_NODE_WIDTH
    ) 
```

Note that storage slots in the same size `VERKLE_NODE_WIDTH` range (ie. a range the form `x*VERKLE_NODE_WIDTH ... (x+1)*VERKLE_NODE_WIDTH-1`) are all, with the exception of the `HEADER_STORAGE_OFFSET` special case, part of a single commitment. This is an optimization to make witnesses more efficient when related storage slots are accessed together. If desired, this optimization can be exposed to the gas schedule, making it more gas-efficient to make contracts that store related slots together (however, Solidity already stores in this way by default).

### Fork

At block number `FORK_HEIGHT`, we replace the `state: PatriciaTree` structure with a `states: Tuple[PatriciaTree, VerkleTree]` structure. The Patricia tree carries over the data from the previous Patricia tree. The Verkle tree starts off empty, though note that it may become nonempty even during block number `FORK_HEIGHT` as a result of activity within that block itself. From that point on, the Patricia tree is immutable, and all modifications happen to the Verkle tree.

Data is saved to the Verkle tree when those fields are _modified_, or when they are simply _accessed_. State is read by first attempting to read the Verkle tree, and only if the Verkle tree is empty at a particular position attempting to read the Patricia tree. Note that setting a value to zero (whether balance or a storage key or anything else) sets the value in the tree at the appropriate position to _zero_, not _empty_.

### Access events

We define **access events** as follows. When an access event takes place, the accessed data is saved to the Verkle tree (even if it was not modified). An access event is of the form `(address, sub_key, leaf_key)`, determining what data is being accessed.

#### Access events for account headers

When a non-precompile `address` is the target of a `CALL`, `CALLCODE`, `DELEGATECALL`, `SELFDESTRUCT`, `EXTCODESIZE`, or `EXTCODECOPY` opcode, or is the target address of a contract creation whose initcode starts execution, process these access events:

```python
(address, 0, VERSION_LEAF_KEY)
(address, 0, CODE_SIZE_LEAF_KEY)
```

If a call is _value-bearing_ (ie. it transfers nonzero wei), whether or not the callee is a precompile, process these two access events:

```python
(caller_address, 0, BALANCE_LEAF_KEY)
(callee_address, 0, BALANCE_LEAF_KEY)
```

When a contract is created, process these access events:

```python
(contract_address, 0, VERSION_LEAF_KEY)
(contract_address, 0, NONCE_LEAF_KEY)
(contract_address, 0, BALANCE_LEAF_KEY)
(contract_address, 0, CODE_KECCAK_LEAF_KEY)
(contract_address, 0, CODE_SIZE_LEAF_KEY)
```

If the `BALANCE` opcode is called targeting some `address`, process this access event:

```python
(address, 0, BALANCE_LEAF_KEY)
```

If the `SELFDESTRUCT` opcode is called by some `caller_address` targeting some `target_address` (regardless of whether it's value-bearing or not), process access events of the form:

```python
(caller_address, 0, BALANCE_LEAF_KEY)
(target_address, 0, BALANCE_LEAF_KEY)
```

If the `EXTCODEHASH` opcode is called targeting some `address`, process an access event of the form:

```python
(address, 0, CODEHASH_LEAF_KEY)
```

#### Access events for storage

`SLOAD` and `SSTORE` opcodes with a given `address` and `key` process an access event of the form

```python
(address, tree_key, sub_key)
```

Where `tree_key` and `sub_key` are computed as follows:

```python
def get_storage_slot_tree_keys(storage_key: int) -> [int, int]:
    if storage_key < (CODE_OFFSET - HEADER_STORAGE_OFFSET):
        pos = HEADER_STORAGE_OFFSET + storage_key
    else:
        pos = MAIN_STORAGE_OFFSET + storage_key
    return (
        pos // 256,
        pos % 256
    ) 
```

#### Access events for code

In the conditions below, "chunk `chunk_id` is accessed" is understood to mean an access event of the form

```python
(address, (chunk_id + 128) // 256, (chunk_id + 128) % 256)
```

* At each step of EVM execution, if and only if `PC < len(code)`, chunk `PC // CHUNK_SIZE` (where `PC` is the current program counter) of the callee is accessed. In particular, note the following corner cases:
    * The destination of a `JUMP` (or positively evaluated `JUMPI`) is considered to be accessed, even if the destination is not a jumpdest or is inside pushdata
    * The destination of a `JUMPI` is not considered to be accessed if the jump conditional is false.
    * The destination of a jump is not considered to be accessed if the execution gets to the jump opcode but does not have enough gas to pay for the gas cost of executing the `JUMP` opcode (including chunk access cost if the `JUMP` is the first opcode in a not-yet-accessed chunk)
    * The destination of a jump is not considered to be accessed if it is beyond the code (`destination >= len(code)`)
    * If code stops execution by walking past the end of the code, `PC = len(code)` is not considered to be accessed
* If the current step of EVM execution is a `PUSH{n}`, all chunks `(PC // CHUNK_SIZE) <= chunk_index <= ((PC + n) // CHUNK_SIZE)` of the callee are accessed.
* If a nonzero-read-size `CODECOPY` or `EXTCODECOPY` read bytes `x...y` inclusive, all chunks `(x // CHUNK_SIZE) <= chunk_index <= (min(y, code_size - 1) // CHUNK_SIZE)` of the accessed contract are accessed.
    *  Example 1: for a `CODECOPY` with start position 100, read size 50, `code_size = 200`, `x = 100` and `y = 149`
    *  Example 2: for a `CODECOPY` with start position 600, read size 0, no chunks are accessed
    *  Example 3: for a `CODECOPY` with start position 1500, read size 2000, `code_size = 3100`, `x = 1500` and `y = 3099`
* `CODESIZE`, `EXTCODESIZE` and `EXTCODEHASH` do NOT access any chunks.
* When a contract is created, access chunks `0 ... (len(code)+30)//31`

### Transactions

For a transaction, make these access events:

```python
(tx.origin, 0, VERSION_LEAF_KEY)
(tx.origin, 0, BALANCE_LEAF_KEY)
(tx.origin, 0, NONCE_LEAF_KEY)
(tx.origin, 0, CODE_SIZE_LEAF_KEY)
(tx.origin, 0, CODE_KECCAK_LEAF_KEY)
(tx.target, 0, VERSION_LEAF_KEY)
(tx.target, 0, BALANCE_LEAF_KEY)
(tx.target, 0, NONCE_LEAF_KEY)
(tx.target, 0, CODE_SIZE_LEAF_KEY)
(tx.target, 0, CODE_KECCAK_LEAF_KEY)
```

### Witness gas costs

| Constant | Value |
| - | - |
| `WITNESS_BRANCH_COST` | 1900 |
| `WITNESS_CHUNK_COST` | 200 |

When executing a transaction, maintain two sets:

* `accessed_subtrees: Set[Tuple[address, int]]`
* `accessed_leaves: Set[Tuple[address, int, int]]`

When an **access event** of `(address, sub_key, leaf_key)` occurs, perform the following checks:

* If `(address, sub_key)` is not in `accessed_subtrees`, charge `WITNESS_BRANCH_COST` gas and add that tuple to `accessed_subtrees`.
* If `leaf_key is not None` and `(address, sub_key, leaf_key)` is not in `accessed_leaves`, charge `WITNESS_CHUNK_COST` gas and add it to `accessed_leaves`

### Replacement for access lists

We replace EIP 2930 access lists with an SSZ structure of the form:

```python
class AccessList(Container):
    addresses: List[AccountAccessList, ACCESS_LIST_MAX_ELEMENTS]
    
class AccountAccessList(Container):
    address: Address32
    subtrees: List[AccessSubtree, ACCESS_LIST_MAX_ELEMENTS]
    
class AccessSubtree(Container):
    subtree_key: uint256
    elements: BitVector[256]
```

### Miscellaneous

* The `SELFDESTRUCT` opcode is renamed to `SENDALL`, and now _only_ immediately moves all ETH in the account to the target; it no longer destroys code or storage or alters the nonce
* All refunds are removed

## Rationale

This implements all of the logic in transitioning to a Verkle tree, and at the same time reforms gas costs, but does so in a minimally disruptive way that does not require simultaneously changing the whole tree structure. Instead, we add a new Verkle tree that starts out empty, and only new changes to state and copies of accessed state are stored in the tree. The Patricia tree continues to exist, but is frozen.

This sets the stage for a future hard fork that swaps the Patricia tree in-place with a Verkle tree storing the same data. Unlike [EIP 2584](https://eips.ethereum.org/EIPS/eip-2584), this replacement Verkle tree does _not_ need to be computed by clients in real time. Instead, because the Patricia tree would at that point be fixed, the replacement Verkle tree can be computed off-chain.

### Verkle tree design

The Verkle tree uses a single-layer tree structure with 32-byte keys and values for several reasons:

* **Simplicity**: working with the abstraction of a key/value store makes it easier to write code dealing with the tree (eg. database reading/writing, caching, syncing, proof creation and verification) as well as to upgrade it to other trees in the future. Additionally, witness gas rules can become simpler and clearer.
* **Uniformity**: the state is uniformly spread out throughout the tree; even if a single contract has many millions of storage slots, the contract's storage slots are not concentrated in one place. This is useful for state syncing algorithms. Additionally, it helps reduce the effectiveness of unbalanced tree filling attacks.
* **Extensibility**: account headers and code being in the same structure as storage makes it easier to extend the features of both, and even add new structures if later desired.

The single-layer tree design _does_ have a major weakness: the inability to deal with entire storage trees as a single object. This is why this EIP includes removing most of the functionality of `SELFDESTRUCT`. If absolutely desired, `SELFDESTRUCT`'s functionality could be kept by adding and incrementing an `account_state_offset` parameter that increments every time an account self-destructs, but this would increase complexity.

### Gas reform

Gas costs for reading storage and code are reformed to more closely reflect the gas costs under the new Verkle tree design. `WITNESS_CHUNK_COST` is set to charge 6.25 gas per byte for chunks, and `WITNESS_BRANCH_COST` is set to charge ~13,2 gas per byte for branches _on average_ (assuming 144 byte branch length) and ~2.5 gas per byte in the worst case if an attacker fills the tree with keys deliberately computed to maximize proof length.

The main differences from gas costs in Berlin are:

* 200 gas charged per 31 byte chunk of code. This has been estimated to increase average gas usage by ~6-12% (see [this analysis](https://notes.ethereum.org/@ipsilon/code-chunk-cost-analysis) suggesting 10-20% gas usage increases at a 350 gas per chunk level).
* Cost for accessing _adjacent_ storage slots (`key1 // 256 == key2 // 256`) decreases from 2100 to 200 for all slots after the first in the group,
* Cost for accessing storage slots 0...63 decreases from 2100 to 200, including the first storage slot. This is likely to significantly improve performance of many existing contracts, which use those storage slots for single persistent variables.

Gains from the latter two properties have not yet been analyzed, but are likely to significantly offset the losses from the first property. It's likely that once compilers adapt to these rules, efficiency will increase further.

The precise specification of when access events take place, which makes up most of the complexity of the gas repricing, is necessary to clearly specify when data needs to be saved to the period 1 tree.

### Forward-compatibility

After the fork, there are two trees: a (no longer changing) hexary Patricia tree for period 0 and a Verkle tree for period 1. At that point we have forward compatibility with two paths:

* Fully implement state expiry, with a subsequent EIP that swaps out the Patricia tree root for a Verkle tree root, begins period 2 and schedules future periods (see [the roadmap](https://notes.ethereum.org/@vbuterin/verkle_and_state_expiry_proposal))
* Abandon state expiry, and slowly move all period 0 data into period 1 (so we just have weak statelessness)

Hence, while this EIP offers a very convenient path to implementing state expiry, it does not force that course of action, and it does leave open the door to simply sticking with weak statelessness.

### Backward-compatibility

The three main backwards-compatibility-breaking changes are:

1. `SELFDESTRUCT` neutering (see [here](https://hackmd.io/@vbuterin/selfdestruct) for a document stating the case for doing this despite the backwards compatibility loss)
2. Gas costs for code chunk access making some applications less economically viable
3. Tree structure change makes in-EVM proofs of historical state no longer work

(2) can be mitigated by increasing the gas limit at the same time as implementing this EIP, reducing the risk that applications will no longer work at all due to transaction gas usage rising above the block gas limit. (3) cannot be mitigated this time, but [this proposal](https://ethresear.ch/t/future-proof-shard-and-history-access-precompiles/9781) could be implemented to make this no longer a concern for any tree structure changes in the future.
