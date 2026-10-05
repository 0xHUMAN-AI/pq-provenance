// End-to-end dry run on Arc mainnet, free: eth_call with a state override places PQProvenance's
// runtime code at a scratch address, and the real SLH-DSA precompile checks real signatures.
import { readFileSync } from "node:fs";
import { decodeErrorResult, decodeFunctionResult, encodeAbiParameters, encodeFunctionData, keccak256, toHex } from "viem";
import { ARC_CHAIN_ID, digests, keygen, sign, uriHash } from "../lib/pqp.js";
import { rpc } from "./probe-precompile.mjs";

const { abi, deployedBytecode } = JSON.parse(readFileSync(new URL("../out/PQProvenance.json", import.meta.url), "utf8"));
const address = "0x000000000000000000000000000000000000beef";
const runtime = deployedBytecode;

async function call(functionName, args) {
  const data = encodeFunctionData({ abi, functionName, args });
  const res = await rpc("eth_call", [{ to: address, data, gas: "0x1c9c380" }, "latest", { [address]: { code: runtime } }]);
  if (res.error) {
    let reason = res.error.message;
    try { reason = decodeErrorResult({ abi, data: res.error.data }).errorName; } catch {}
    return { error: reason };
  }
  return { result: decodeFunctionResult({ abi, functionName, data: res.result }) };
}

const ctx = { chainId: ARC_CHAIN_ID, address };
const k = keygen(new Uint8Array(48).fill(7));
const label = toHex("dry-run", { size: 32 });
console.log("verifier()        ", await call("VERIFIER", []));
console.log("digest matches JS ", (await call("registerDigest", [k.vk, label])).result === digests.register(ctx, k.vk, label));
console.log("register, real sig", await call("register", [k.vk, label, sign(k.secretKey, digests.register(ctx, k.vk, label))]));
const other = keygen(new Uint8Array(48).fill(8));
console.log("register, bad sig ", await call("register", [k.vk, label, sign(other.secretKey, digests.register(ctx, k.vk, label))]));
const est = await rpc("eth_estimateGas", [{ to: address, data: encodeFunctionData({ abi, functionName: "register", args: [k.vk, label, sign(k.secretKey, digests.register(ctx, k.vk, label))] }) }, "latest", { [address]: { code: runtime } }]);
console.log("register gas      ", est.result ? BigInt(est.result) : est.error);

// The other write paths, with state seeded through the override: storage slots follow the declaration
// order (keys 0, attestations 1, codeAttestations 2); a Key or Attestation word of 1 means Active or attested.
const slot = (key, base) => keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }], [key, base]));
const one = `0x${"00".repeat(31)}01`;
const subject = keccak256(toHex("dry-run-release"));
const codehash = keccak256(runtime);
const state = {
  [slot(k.vk, 0n)]: one,
  [slot(subject, BigInt(slot(k.vk, 1n)))]: one,
  [slot(codehash, BigInt(slot(k.vk, 2n)))]: one,
};
async function seeded(functionName, args) {
  const data = encodeFunctionData({ abi, functionName, args });
  const res = await rpc("eth_call", [{ to: address, data, gas: "0x1c9c380" }, "latest", { [address]: { code: runtime, stateDiff: state }, [twin]: { code: "0x6000" } }]);
  if (res.error) {
    let reason = res.error.message;
    try { reason = decodeErrorResult({ abi, data: res.error.data }).errorName; } catch {}
    return { error: reason };
  }
  return { result: decodeFunctionResult({ abi, functionName, data: res.result }) };
}
const twin = "0x000000000000000000000000000000000000cafe";
const fresh = keccak256(toHex("dry-run-release-2"));
console.log("seeded key active ", (await seeded("keys", [k.vk])).result?.[0] === 1);
console.log("attest, real sig  ", await seeded("attest", [k.vk, fresh, "", sign(k.secretKey, digests.attest(ctx, k.vk, fresh, uriHash("")))]));
console.log("attest, bad sig   ", await seeded("attest", [k.vk, fresh, "", sign(other.secretKey, digests.attest(ctx, k.vk, fresh, uriHash("")))]));
console.log("attestCode, seeded", await seeded("attestCode", [k.vk, address, sign(k.secretKey, digests.attestCode(ctx, k.vk, address, codehash))]), "(expected AlreadyAttested)");
const twinHash = keccak256("0x6000");
console.log("attestCode, other ", await seeded("attestCode", [k.vk, twin, sign(k.secretKey, digests.attestCode(ctx, k.vk, twin, twinHash))]));
console.log("isCodeAttested    ", (await seeded("isCodeAttested", [k.vk, address])).result, (await seeded("isCodeAttested", [k.vk, twin])).result);
console.log("retract, real sig ", await seeded("retract", [k.vk, subject, sign(k.secretKey, digests.retract(ctx, k.vk, subject))]));
console.log("retractCode, real ", await seeded("retractCode", [k.vk, codehash, sign(k.secretKey, digests.retractCode(ctx, k.vk, codehash))]));
console.log("retractCode, data ", await seeded("retractCode", [k.vk, codehash, sign(k.secretKey, digests.retract(ctx, k.vk, codehash))]));
