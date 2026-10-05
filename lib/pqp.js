// Client helpers for PQProvenance: digests (mirroring the contract), SLH-DSA keys and signatures.
import { slh_dsa_sha2_128s as slh } from "@noble/post-quantum/slh-dsa.js";
import { encodeAbiParameters, keccak256, toBytes, toHex } from "viem";

export const PQ_PRECOMPILE = "0x1800000000000000000000000000000000000004";
export const ARC_CHAIN_ID = 5042n;

const enc = (types, values) => keccak256(encodeAbiParameters(types.map((type) => ({ type })), values));
const head = ["string", "uint256", "address", "bytes32"];

export const digests = {
  register: (c, vk, label) => enc([...head, "bytes32"], ["PQP/register", c.chainId, c.address, vk, label]),
  attest: (c, vk, subject, uriHash) =>
    enc([...head, "bytes32", "bytes32"], ["PQP/attest", c.chainId, c.address, vk, subject, uriHash]),
  attestCode: (c, vk, target, codehash) =>
    enc([...head, "address", "bytes32"], ["PQP/attest-code", c.chainId, c.address, vk, target, codehash]),
  retract: (c, vk, subject) => enc([...head, "bytes32"], ["PQP/retract", c.chainId, c.address, vk, subject]),
  retractCode: (c, vk, codehash) =>
    enc([...head, "bytes32"], ["PQP/retract-code", c.chainId, c.address, vk, codehash]),
  rotate: (c, vk, successor) => enc([...head, "bytes32"], ["PQP/rotate", c.chainId, c.address, vk, successor]),
  revoke: (c, vk) => enc(head, ["PQP/revoke", c.chainId, c.address, vk]),
};

export const uriHash = (uri) => (uri ? keccak256(toBytes(uri)) : `0x${"00".repeat(32)}`);

/** Deterministic key from a 48-byte seed (keep it secret), or a random one without a seed. */
export function keygen(seed) {
  const k = slh.keygen(seed);
  return { vk: toHex(k.publicKey), secretKey: k.secretKey };
}

/** Signs a 32-byte digest; the result is the 7856-byte signature the contract expects. */
export const sign = (secretKey, digest) => toHex(slh.sign(toBytes(digest), secretKey));

export const verify = (vk, digest, sig) => slh.verify(toBytes(sig), toBytes(digest), toBytes(vk));
