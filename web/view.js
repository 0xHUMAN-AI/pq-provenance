// Read-only client for PQProvenance: hand-rolled ABI for the view functions, no dependencies, so the
// page runs from a static host with nothing but the browser and Arc's public RPC.

export const ARC_RPC = "https://rpc.mainnet.arc.io";
export const ARC_CHAIN_ID = 5042;

// Selectors of the views the page calls; test/view.test.mjs checks them against the compiled ABI.
export const SELECTORS = {
  keys: "0xdde5b7a1",
  attestations: "0x92abd17b",
  codeAttestations: "0x3c3bf730",
  isAttested: "0x98617ff8",
  isCodeAttested: "0x93e25f1e",
  currentKey: "0x27680443",
  attestationCount: "0xd65ddd52",
};

export const STATUS = ["unknown", "active", "rotated", "revoked"];

const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export function word(value) {
  if (HEX32.test(value)) return value.slice(2).toLowerCase();
  if (ADDRESS.test(value)) return value.slice(2).toLowerCase().padStart(64, "0");
  throw new Error(`not a bytes32 or address: ${value}`);
}

export const encode = (fn, ...args) => SELECTORS[fn] + args.map(word).join("");

function words(hex) {
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (body.length === 0 || body.length % 64 !== 0) throw new Error(`unexpected return data: ${hex}`);
  return body.match(/.{64}/g);
}

const uint = (w) => BigInt(`0x${w}`);
const time = (w) => Number(uint(w));

export const decode = {
  bool: (hex) => uint(words(hex)[0]) === 1n,
  bytes32: (hex) => `0x${words(hex)[0]}`,
  uint: (hex) => uint(words(hex)[0]),
  key: (hex) => {
    const [status, registeredAt, closedAt, successor, label] = words(hex);
    return { status: STATUS[Number(uint(status))], registeredAt: time(registeredAt), closedAt: time(closedAt), successor: `0x${successor}`, label: `0x${label}` };
  },
  attestation: (hex) => {
    const [attestedAt, retractedAt, uriHash] = words(hex);
    return { attestedAt: time(attestedAt), retractedAt: time(retractedAt), uriHash: `0x${uriHash}` };
  },
};

/** `call(data)` returns the raw hex of an eth_call to the registry; the default goes to Arc's RPC. */
export function rpcCaller(contract, rpc = ARC_RPC, fetchImpl = fetch) {
  return async (data) => {
    const res = await fetchImpl(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: contract, data }, "latest"] }),
    });
    const body = await res.json();
    if (body.error) throw new Error(body.error.message ?? "eth_call failed");
    return body.result;
  };
}

/** Everything the page shows about a key: status, label, successor chain end, attestation count. */
export async function keyInfo(call, vk) {
  const key = decode.key(await call(encode("keys", vk)));
  const count = decode.uint(await call(encode("attestationCount", vk)));
  let current = vk;
  try {
    current = decode.bytes32(await call(encode("currentKey", vk)));
  } catch {
    current = null; // rotation chain longer than 64 hops: the contract refuses to name an end
  }
  return { ...key, attestationCount: count, currentKey: current };
}

/** Status of a data subject (for files: the SHA-256 of their bytes) under one key. */
export async function subjectInfo(call, vk, subject) {
  const record = decode.attestation(await call(encode("attestations", vk, subject)));
  return { ...record, valid: decode.bool(await call(encode("isAttested", vk, subject))) };
}

/** Whether the code now deployed at `target` is attested by `vk`. */
export async function codeInfo(call, vk, target) {
  return { valid: decode.bool(await call(encode("isCodeAttested", vk, target))) };
}

/** SHA-256 of a file's bytes as 0x-hex: the subject convention for files. */
export async function fileSubject(bytes, subtle = globalThis.crypto.subtle) {
  const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
  return `0x${Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export function labelText(label) {
  const bytes = label.slice(2).match(/.{2}/g).map((h) => parseInt(h, 16));
  const end = bytes.indexOf(0);
  return new TextDecoder().decode(new Uint8Array(end === -1 ? bytes : bytes.slice(0, end)));
}
