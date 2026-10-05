// Checks real SLH-DSA-SHA2-128s signatures against Arc's precompile with eth_call (free, read-only).
import { slh_dsa_sha2_128s as slh } from "@noble/post-quantum/slh-dsa.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export const RPC = process.env.ARC_RPC ?? "https://rpc.mainnet.arc.io";
export const PQ = "0x1800000000000000000000000000000000000004";
const SIG = "verifySlhDsaSha2128s(bytes,bytes,bytes)";
export const SELECTOR = bytesToHex(keccak_256(utf8ToBytes(SIG))).slice(0, 8);

const word = (n) => n.toString(16).padStart(64, "0");
function encodeBytes(parts) {
  // ABI-encode (bytes, bytes, bytes)
  let head = "", tail = "", offset = 32 * parts.length;
  for (const p of parts) {
    head += word(offset);
    const padded = bytesToHex(p).padEnd(Math.ceil(p.length / 32) * 64, "0");
    tail += word(p.length) + padded;
    offset += 32 + Math.ceil(p.length / 32) * 32;
  }
  return head + tail;
}

export const calldata = (vk, msg, sig) => "0x" + SELECTOR + encodeBytes([vk, msg, sig]);

export async function rpc(method, params) {
  return fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  }).then((r) => r.json());
}

export async function verifyOnChain(vk, msg, sig) {
  const res = await rpc("eth_call", [{ to: PQ, data: calldata(vk, msg, sig) }, "latest"]);
  if (res.error) return { error: res.error.message };
  return { ok: BigInt(res.result) === 1n, raw: res.result };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const seed = hexToBytes("00".repeat(48));
  const k = slh.keygen(seed);
  const msg = keccak_256(utf8ToBytes("pq-provenance probe"));
  const sig = slh.sign(msg, k.secretKey);
  console.log("selector", SELECTOR, "vk", k.publicKey.length, "sig", sig.length);
  console.log("valid      ", await verifyOnChain(k.publicKey, msg, sig));
  const bad = sig.slice(); bad[100] ^= 1;
  console.log("tampered   ", await verifyOnChain(k.publicKey, msg, bad));
  const other = msg.slice(); other[0] ^= 1;
  console.log("other msg  ", await verifyOnChain(k.publicKey, other, sig));
  const raw = utf8ToBytes("hello arc, a message of arbitrary length");
  const gas = await rpc("eth_estimateGas", [{ to: PQ, data: calldata(k.publicKey, msg, sig) }]);
  console.log("gas        ", gas.result ? BigInt(gas.result) : gas.error);
  console.log("raw msg    ", await verifyOnChain(k.publicKey, raw, slh.sign(raw, k.secretKey)));
}
