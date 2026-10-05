import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { before, test } from "node:test";
import { keccak256, toFunctionSelector, toHex } from "viem";
import { digests, keygen, sign, uriHash } from "../lib/pqp.js";
import { codeInfo, encode, fileSubject, keyInfo, labelText, rpcCaller, SELECTORS, subjectInfo } from "../web/view.js";
import { artifact, CHAIN_ID, setup } from "./harness.mjs";

const A = keygen(new Uint8Array(48).fill(7));
const B = keygen(new Uint8Array(48).fill(8));
const label = toHex("acme-releases", { size: 32 });
const file = new TextEncoder().encode("release-1.0.0 contents\n");
const uri = "https://example.org/release-1.0.0.tar.gz";

let env, pqp, ctx, subject;
before(async () => {
  env = await setup();
  pqp = await env.deploy("PQProvenance");
  ctx = { chainId: CHAIN_ID, address: pqp.address };
  subject = await fileSubject(file);
});

test("page selectors match the compiled ABI", () => {
  const abi = artifact("PQProvenance").abi;
  for (const [name, selector] of Object.entries(SELECTORS)) {
    assert.equal(selector, toFunctionSelector(abi.find((f) => f.type === "function" && f.name === name)), name);
  }
});

test("file subject is the SHA-256 of the bytes", () => {
  assert.equal(subject, `0x${createHash("sha256").update(file).digest("hex")}`);
});

test("encode refuses malformed arguments", () => {
  assert.throws(() => encode("keys", "0x1234"));
  assert.throws(() => encode("keys", `0x${"zz".repeat(32)}`));
});

test("unknown key and subject read as unknown and invalid", async () => {
  const info = await keyInfo(pqp.call, A.vk);
  assert.equal(info.status, "unknown");
  assert.equal(info.attestationCount, 0n);
  assert.equal((await subjectInfo(pqp.call, A.vk, subject)).valid, false);
});

test("views follow register, attest, rotate and retract", async () => {
  await pqp.run("register", [A.vk, label, sign(A.secretKey, digests.register(ctx, A.vk, label))]);
  await pqp.run("attest", [A.vk, subject, uri, sign(A.secretKey, digests.attest(ctx, A.vk, subject, uriHash(uri)))]);
  let info = await keyInfo(pqp.call, A.vk);
  assert.equal(info.status, "active");
  assert.equal(labelText(info.label), "acme-releases");
  assert.equal(info.attestationCount, 1n);
  assert.equal(info.currentKey, A.vk);
  let s = await subjectInfo(pqp.call, A.vk, subject);
  assert.equal(s.valid, true);
  assert.equal(s.uriHash, uriHash(uri));
  assert.ok(s.attestedAt > 0);

  const rot = digests.rotate(ctx, A.vk, B.vk);
  assert.equal((await pqp.run("rotate", [A.vk, B.vk, sign(A.secretKey, rot), sign(B.secretKey, rot)])).error, undefined);
  info = await keyInfo(pqp.call, A.vk);
  assert.equal(info.status, "rotated");
  assert.equal(info.currentKey, B.vk);
  assert.equal(info.successor, B.vk);
  assert.equal((await subjectInfo(pqp.call, A.vk, subject)).valid, true, "rotated keys keep past attestations");

  await pqp.run("retract", [A.vk, subject, sign(A.secretKey, digests.retract(ctx, A.vk, subject))]);
  s = await subjectInfo(pqp.call, A.vk, subject);
  assert.equal(s.valid, false);
  assert.ok(s.retractedAt >= s.attestedAt);
});

test("code view: the registry's own code, attested and not", async () => {
  assert.equal((await codeInfo(pqp.call, B.vk, pqp.address)).valid, false);
  const codehash = keccak256(artifact("PQProvenance").deployedBytecode);
  const sig = sign(B.secretKey, digests.attestCode(ctx, B.vk, pqp.address, codehash));
  assert.equal((await pqp.run("attestCode", [B.vk, pqp.address, sig])).error, undefined);
  assert.equal((await codeInfo(pqp.call, B.vk, pqp.address)).valid, true);
});

test("rpcCaller sends eth_call and surfaces RPC errors", async () => {
  const seen = [];
  const fake = async (url, init) => {
    seen.push([url, JSON.parse(init.body)]);
    return { json: async () => (seen.length === 1 ? { result: "0x01" } : { error: { message: "execution reverted" } }) };
  };
  const call = rpcCaller(pqp.address, "https://rpc.example", fake);
  assert.equal(await call("0xdeadbeef"), "0x01");
  assert.deepEqual(seen[0][1].params, [{ to: pqp.address, data: "0xdeadbeef" }, "latest"]);
  await assert.rejects(call("0xdeadbeef"), /execution reverted/);
});
