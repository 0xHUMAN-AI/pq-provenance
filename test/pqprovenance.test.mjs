import assert from "node:assert/strict";
import { before, test } from "node:test";
import { encodeAbiParameters, keccak256, toHex } from "viem";
import { digests, keygen, sign, uriHash } from "../lib/pqp.js";
import { CHAIN_ID, precompileCalls, setup } from "./harness.mjs";

const seed = (n) => new Uint8Array(48).fill(n);
const A = keygen(seed(1));
const B = keygen(seed(2));
const C = keygen(seed(3));
const label = toHex("acme-releases", { size: 32 });
const subject = keccak256(toHex("release-1.0.0.tar.gz"));
const uri = "https://example.org/release-1.0.0.tar.gz";

let env, pqp, ctx;
before(async () => {
  env = await setup();
  pqp = await env.deploy("PQProvenance");
  ctx = { chainId: CHAIN_ID, address: pqp.address };
});

test("JS digests match the contract", async () => {
  assert.equal(await pqp.read("registerDigest", [A.vk, label]), digests.register(ctx, A.vk, label));
  assert.equal(await pqp.read("attestDigest", [A.vk, subject, uriHash(uri)]), digests.attest(ctx, A.vk, subject, uriHash(uri)));
  assert.equal(await pqp.read("attestCodeDigest", [A.vk, pqp.address, subject]), digests.attestCode(ctx, A.vk, pqp.address, subject));
  assert.equal(await pqp.read("retractDigest", [A.vk, subject]), digests.retract(ctx, A.vk, subject));
  assert.equal(await pqp.read("retractCodeDigest", [A.vk, subject]), digests.retractCode(ctx, A.vk, subject));
  assert.equal(await pqp.read("rotateDigest", [A.vk, B.vk]), digests.rotate(ctx, A.vk, B.vk));
  assert.equal(await pqp.read("revokeDigest", [A.vk]), digests.revoke(ctx, A.vk));
});

test("register needs a proof of possession", async () => {
  const wrongKeySig = sign(B.secretKey, digests.register(ctx, A.vk, label));
  assert.equal((await pqp.run("register", [A.vk, label, wrongKeySig])).error, "BadSignature");
  assert.equal((await pqp.run("register", [A.vk, label, "0x1234"])).error, "BadSignature");
  const zero = `0x${"00".repeat(32)}`;
  assert.equal((await pqp.run("register", [zero, label, wrongKeySig])).error, "ZeroValue");
  const ok = await pqp.run("register", [A.vk, label, sign(A.secretKey, digests.register(ctx, A.vk, label))]);
  assert.equal(ok.error, undefined);
  assert.equal(precompileCalls.at(-1), digests.register(ctx, A.vk, label), "the precompile sees the digest");
  const k = await pqp.read("keys", [A.vk]);
  assert.equal(k[0], 1, "Active");
  assert.equal(k[4], label);
  const again = await pqp.run("register", [A.vk, label, sign(A.secretKey, digests.register(ctx, A.vk, label))]);
  assert.equal(again.error, "KeyExists");
});

test("attest binds subject and uri; a relayer cannot swap the uri", async () => {
  const sig = sign(A.secretKey, digests.attest(ctx, A.vk, subject, uriHash(uri)));
  assert.equal((await pqp.run("attest", [A.vk, subject, "https://evil.example", sig])).error, "BadSignature");
  assert.equal(await pqp.read("isAttested", [A.vk, subject]), false);
  const ok = await pqp.run("attest", [A.vk, subject, uri, sig]);
  assert.equal(ok.error, undefined);
  console.log(`attest gas (emulated precompile at 200k): ${ok.gas}`);
  assert.equal(await pqp.read("isAttested", [A.vk, subject]), true);
  assert.equal(await pqp.read("attestationCount", [A.vk]), 1n);
  assert.equal((await pqp.run("attest", [A.vk, subject, uri, sig])).error, "AlreadyAttested");
  assert.equal(await pqp.read("isAttested", [B.vk, subject]), false);
});

test("an unregistered key cannot attest", async () => {
  const sig = sign(C.secretKey, digests.attest(ctx, C.vk, subject, uriHash("")));
  assert.equal((await pqp.run("attest", [C.vk, subject, "", sig])).error, "KeyNotActive");
});

test("attestCode follows the code at the address", async () => {
  const codehash = await codehashOf(pqp.address);
  // A data attestation whose subject equals a codehash must not vouch for code.
  const dataSig = sign(A.secretKey, digests.attest(ctx, A.vk, codehash, uriHash("")));
  assert.equal((await pqp.run("attest", [A.vk, codehash, "", dataSig])).error, undefined);
  assert.equal(await pqp.read("isCodeAttested", [A.vk, pqp.address]), false, "data subject is not code");
  // Nor may a data attestation of the old code namespace (an opaque hash handed to a blind signer).
  const oldNs = keccak256(encodeAbiParameters([{ type: "string" }, { type: "bytes32" }], ["PQP/code", codehash]));
  const nsSig = sign(A.secretKey, digests.attest(ctx, A.vk, oldNs, uriHash("")));
  assert.equal((await pqp.run("attest", [A.vk, oldNs, "", nsSig])).error, undefined);
  assert.equal(await pqp.read("isCodeAttested", [A.vk, pqp.address]), false, "data namespace cannot reach code");
  const sig = sign(A.secretKey, digests.attestCode(ctx, A.vk, pqp.address, codehash));
  assert.equal((await pqp.run("attestCode", [A.vk, pqp.address, sig])).error, undefined);
  assert.equal(await pqp.read("isCodeAttested", [A.vk, pqp.address]), true);
  assert.equal(await pqp.read("isAttested", [A.vk, codehash]), true, "the data attestation is still there");
  const swapped = sign(A.secretKey, digests.retract(ctx, A.vk, codehash));
  assert.equal((await pqp.run("retractCode", [A.vk, codehash, swapped])).error, "BadSignature", "a data retract is not a code retract");
  const dataRetract = sign(A.secretKey, digests.retract(ctx, A.vk, codehash));
  assert.equal((await pqp.run("retract", [A.vk, codehash, dataRetract])).error, undefined);
  assert.equal(await pqp.read("isCodeAttested", [A.vk, pqp.address]), true, "retracting the data subject leaves code");
  const twin = await env.deploy("PQProvenance");
  assert.equal(await pqp.read("isCodeAttested", [A.vk, twin.address]), true, "same runtime code, same codehash");
  const eoa = "0x00000000000000000000000000000000000000aa";
  assert.equal(await pqp.read("isCodeAttested", [A.vk, eoa]), false);
  const eoaSig = sign(A.secretKey, digests.attestCode(ctx, A.vk, eoa, keccak256("0x")));
  assert.equal((await pqp.run("attestCode", [A.vk, eoa, eoaSig])).error, "NoCode");
});

test("signatures do not replay across deployments, chains or actions", async () => {
  const other = await env.deploy("PQProvenance");
  const sig = sign(A.secretKey, digests.register(ctx, A.vk, label));
  assert.equal((await other.run("register", [A.vk, label, sig])).error, "BadSignature");
  const otherChain = sign(C.secretKey, digests.register({ ...ctx, chainId: 1n }, C.vk, label));
  assert.equal((await pqp.run("register", [C.vk, label, otherChain])).error, "BadSignature");
  assert.equal((await pqp.run("revoke", [A.vk, sig])).error, "BadSignature", "a register signature is not a revoke");
});

test("retract withdraws one attestation", async () => {
  const sig = sign(A.secretKey, digests.retract(ctx, A.vk, subject));
  assert.equal((await pqp.run("retract", [A.vk, subject, sig])).error, undefined);
  assert.equal(await pqp.read("isAttested", [A.vk, subject]), false);
  assert.equal((await pqp.run("retract", [A.vk, subject, sig])).error, "NotAttested");
  const again = sign(A.secretKey, digests.attest(ctx, A.vk, subject, uriHash(uri)));
  assert.equal((await pqp.run("attest", [A.vk, subject, uri, again])).error, "AlreadyAttested", "no silent re-attest");
});

test("retractCode withdraws a code attestation only", async () => {
  const D = keygen(seed(4));
  const reg = sign(D.secretKey, digests.register(ctx, D.vk, label));
  assert.equal((await pqp.run("register", [D.vk, label, reg])).error, undefined);
  const ch = await codehashOf(pqp.address);
  assert.equal((await pqp.run("attestCode", [D.vk, pqp.address, sign(D.secretKey, digests.attestCode(ctx, D.vk, pqp.address, ch))])).error, undefined);
  assert.equal((await pqp.run("attest", [D.vk, ch, "", sign(D.secretKey, digests.attest(ctx, D.vk, ch, uriHash("")))])).error, undefined);
  const r = sign(D.secretKey, digests.retractCode(ctx, D.vk, ch));
  assert.equal((await pqp.run("retractCode", [D.vk, ch, r])).error, undefined);
  assert.equal(await pqp.read("isCodeAttested", [D.vk, pqp.address]), false);
  assert.equal(await pqp.read("isAttested", [D.vk, ch]), true, "the data subject with the same bytes stays");
  assert.equal((await pqp.run("retractCode", [D.vk, ch, r])).error, "NotAttested");
  const again = sign(D.secretKey, digests.attestCode(ctx, D.vk, pqp.address, ch));
  assert.equal((await pqp.run("attestCode", [D.vk, pqp.address, again])).error, "AlreadyAttested", "no silent re-attest");
});

test("rotate needs both keys and keeps past attestations", async () => {
  const d = digests.rotate(ctx, A.vk, B.vk);
  const sigA = sign(A.secretKey, d);
  assert.equal((await pqp.run("rotate", [A.vk, B.vk, sigA, sigA])).error, "BadSignature");
  assert.equal((await pqp.run("rotate", [A.vk, B.vk, sigA, sign(B.secretKey, d)])).error, undefined);
  assert.equal((await pqp.read("keys", [A.vk]))[0], 2, "Rotated");
  assert.equal((await pqp.read("keys", [B.vk]))[0], 1, "successor Active");
  assert.equal(await pqp.read("currentKey", [A.vk]), B.vk);
  assert.equal(await pqp.read("isCodeAttested", [A.vk, pqp.address]), true);
  const s2 = keccak256(toHex("release-2.0.0"));
  const late = sign(A.secretKey, digests.attest(ctx, A.vk, s2, uriHash("")));
  assert.equal((await pqp.run("attest", [A.vk, s2, "", late])).error, "KeyNotActive");
  const fresh = sign(B.secretKey, digests.attest(ctx, B.vk, s2, uriHash("")));
  assert.equal((await pqp.run("attest", [B.vk, s2, "", fresh])).error, undefined);
});

test("revoke invalidates every attestation of the key", async () => {
  const s2 = keccak256(toHex("release-2.0.0"));
  assert.equal(await pqp.read("isAttested", [B.vk, s2]), true);
  const sig = sign(B.secretKey, digests.revoke(ctx, B.vk));
  assert.equal((await pqp.run("revoke", [B.vk, sig])).error, undefined);
  assert.equal(await pqp.read("isAttested", [B.vk, s2]), false);
  assert.equal((await pqp.run("revoke", [B.vk, sig])).error, "KeyNotActive");
  assert.equal(await pqp.read("currentKey", [A.vk]), B.vk, "chain ends at the revoked key; callers check its status");
});

test("a rotated key can still be revoked, which voids its past attestations", async () => {
  assert.equal(await pqp.read("isCodeAttested", [A.vk, pqp.address]), true);
  const sig = sign(A.secretKey, digests.revoke(ctx, A.vk));
  assert.equal((await pqp.run("revoke", [A.vk, sig])).error, undefined);
  assert.equal((await pqp.read("keys", [A.vk]))[0], 3, "Revoked");
  assert.equal(await pqp.read("isCodeAttested", [A.vk, pqp.address]), false);
  const ch = await codehashOf(pqp.address);
  const r = sign(A.secretKey, digests.retractCode(ctx, A.vk, ch));
  assert.equal((await pqp.run("retractCode", [A.vk, ch, r])).error, "KeyNotActive");
});

async function codehashOf(address) {
  const { createAddressFromString } = await import("@ethereumjs/util");
  const code = await env.evm.stateManager.getCode(createAddressFromString(address));
  return keccak256(toHex(code));
}
