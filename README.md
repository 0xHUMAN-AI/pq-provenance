# PQ Provenance

A post-quantum provenance registry on Arc. A publisher is an SLH-DSA-SHA2-128s public key; every
registration, attestation, retraction, rotation and revocation is authorised by a signature that Arc
verifies on-chain through its native precompile at `0x1800000000000000000000000000000000000004`.
Anyone can relay a signed action and pay the gas. Contracts can call `isAttested(vk, subject)` or
`isCodeAttested(vk, target)` before trusting a file hash or a contract's runtime code.

No admin, no upgrade path, no funds held.

## Deployment

Arc mainnet (chain ID 5042): `0xA0E319147b11Fc133Bf725Cb547D994eA0AD15dc`, deployed on 2026-10-04 in
transaction `0xa62a3fc52e39ceb8fc1ad2a8be216af8b364257a75d9fe9be4ba25fa00820367` (block 24254720).
The runtime code on chain is byte-identical to `deployedBytecode` from `npm run build` (solc 0.8.30).

Maintainer key: `0x975c1cd45cabf2c8d8ffef0142294118ef741219a2b8269c25d2011fcd8a06e4` (label `pqp-maintainer`),
registered on 2026-10-05 in transaction `0xd14a6fa01bf3934fa1f48b0eae20c9ea7c9b65c3e419f3ff31b0902f344822e3`.
The same key attests the registry's own runtime code (codehash
`0x0657707f08715749ab9cc66e6b799483c9ad9f54ac8ae2477b7dfb1971e75812`) in transaction
`0xa9aba54cf5f812ee47f2866939c0d97bbe9b73f8e5398c486cbcc46f34a53978`, so
`isCodeAttested(maintainer, registry)` returns true.

Source verified on Sourcify, exact match of creation and runtime code:
https://repo.sourcify.dev/5042/0xA0E319147b11Fc133Bf725Cb547D994eA0AD15dc

## Commands

```sh
npm install
npm run build                       # solc 0.8.30 -> out/
npm test                            # in-memory EVM, precompile emulated with @noble/post-quantum
npm run probe                       # real signatures against Arc's precompile (eth_call, free)
node scripts/mainnet-dryrun.mjs     # full contract on Arc mainnet via eth_call state override (free)
python3 -m http.server -d web       # read-only checker page: web/index.html
```

## Checker page

`web/index.html` is a static page with no dependencies: it reads the registry through Arc's public RPC
(`web/view.js`, a hand-rolled ABI for the views, tested against the compiled ABI and the in-memory EVM)
and shows a key's status, whether a file or a contract is attested by it, and when. A file's subject is
the SHA-256 of its bytes, computed in the browser; the file is never uploaded. Prefill with
`?registry=0x…&vk=0x…`.

Live, served from `web/` by GitHub Pages (`.github/workflows/pages.yml`), with the maintainer key:
https://0xhuman-ai.github.io/pq-provenance/?vk=0x975c1cd45cabf2c8d8ffef0142294118ef741219a2b8269c25d2011fcd8a06e4

## Digests

Each action signs `keccak256(abi.encode(tag, chainid, contract, vk, ...))`, so a signature is bound to
one chain, one deployment and one action. `lib/pqp.js` mirrors the contract's digest functions; a test
checks that both agree.

## Security model

What the views mean, and what they do not (from the written red-team of 2026-10-02):

- `isAttested(vk, subject)`: `vk` signed `subject`, did not retract it, and is not revoked. Rotated
  keys keep their past attestations. Pin `vk`; a `label` is free text anyone can claim.
- `isCodeAttested(vk, target)`: the bytecode now at `target` was attested by `vk`. It covers that
  bytecode at any address, not the address itself. Proxies with identical code share one codehash
  whatever implementation they point to, so attest implementations, not proxies. On an EIP-7702
  account the codehash is the delegation designator, so the attestation only says where it delegates.
- Code attestations live in their own mapping (`codeAttestations`), signed with their own digests
  (`attestCodeDigest`, `retractCodeDigest`): no data attestation, whatever 32 bytes it signs, can make
  `isCodeAttested` true, and a file whose hash equals a codehash proves nothing about that code.
  Withdraw them with `retractCode`. Retraction is final for code too, and `CodeRetracted` carries the
  codehash, not the address. `attestationCount` counts data and code attestations ever made; retractions
  do not lower it.
- Revocation does not follow rotations. A thief holding key A can rotate A to a key of their own; the
  owner can revoke A, but not the thief's successor. Integrators should treat the chain from a revoked
  key with suspicion and pin the keys they trust.
- A rotated key keeps the power to retract and revoke, so retired secret keys must stay secret.
- Signed actions carry no expiry: a signature handed to someone can be submitted later while the key
  is active. A retraction is final; a subject cannot be attested again by the same key.
- The precompile call fails closed: a revert, empty or malformed return data all revert the action.
