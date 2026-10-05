// In-memory EVM with Arc's SLH-DSA precompile emulated by @noble/post-quantum.
import { createCustomCommon, Hardfork, Mainnet } from "@ethereumjs/common";
import { createEVM } from "@ethereumjs/evm";
import { createAddressFromString, hexToBytes } from "@ethereumjs/util";
import { slh_dsa_sha2_128s as slh } from "@noble/post-quantum/slh-dsa.js";
import { readFileSync } from "node:fs";
import { decodeErrorResult, decodeFunctionData, decodeFunctionResult, encodeDeployData, encodeFunctionData, toHex } from "viem";
import { PQ_PRECOMPILE } from "../lib/pqp.js";

export const CHAIN_ID = 5042n;
const precompileAbi = [
  {
    type: "function",
    name: "verifySlhDsaSha2128s",
    stateMutability: "view",
    inputs: [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
    outputs: [{ type: "bool" }],
  },
];

export const precompileCalls = [];

function slhPrecompile({ data }) {
  const { args } = decodeFunctionData({ abi: precompileAbi, data: toHex(data) });
  const [vk, msg, sig] = args.map((h) => hexToBytes(h));
  precompileCalls.push(toHex(msg));
  const ok = vk.length === 32 && slh.verify(sig, msg, vk);
  return { executionGasUsed: 200_000n, returnValue: hexToBytes(`0x${(ok ? 1n : 0n).toString(16).padStart(64, "0")}`) };
}

export const artifact = (name) => JSON.parse(readFileSync(new URL(`../out/${name}.json`, import.meta.url), "utf8"));

export async function setup() {
  const common = createCustomCommon({ chainId: Number(CHAIN_ID) }, Mainnet, { hardfork: Hardfork.Cancun });
  const evm = await createEVM({
    common,
    customPrecompiles: [{ address: createAddressFromString(PQ_PRECOMPILE), function: slhPrecompile }],
  });
  const caller = createAddressFromString("0x00000000000000000000000000000000000c0ffe");
  let timestamp = 1_790_000_000n;
  const block = () => ({ header: { timestamp, number: 1n, baseFeePerGas: 0n, prevRandao: new Uint8Array(32), coinbase: caller, gasLimit: 30_000_000n, getBlobGasPrice: () => 0n } });

  async function deploy(name, args = []) {
    const { abi, bytecode } = artifact(name);
    const res = await evm.runCall({ caller, data: hexToBytes(encodeDeployData({ abi, bytecode, args })), gasLimit: 10_000_000n, block: block() });
    if (res.execResult.exceptionError) throw new Error(`deploy ${name}: ${res.execResult.exceptionError.error}`);
    const address = res.createdAddress.toString();
    return contract(abi, address);
  }

  function contract(abi, address) {
    const to = createAddressFromString(address);
    const run = async (functionName, args = []) => {
      const data = hexToBytes(encodeFunctionData({ abi, functionName, args }));
      const res = await evm.runCall({ caller, to, data, gasLimit: 10_000_000n, block: block() });
      const ret = toHex(res.execResult.returnValue);
      if (res.execResult.exceptionError) {
        let name = res.execResult.exceptionError.error;
        try { name = decodeErrorResult({ abi, data: ret }).errorName; } catch {}
        return { error: name, gas: res.execResult.executionGasUsed };
      }
      return { result: decodeFunctionResult({ abi, functionName, data: ret }), gas: res.execResult.executionGasUsed, logs: res.execResult.logs ?? [] };
    };
    // Raw eth_call: hex calldata in, hex return data out, as a JSON-RPC node answers.
    const call = async (data) => toHex((await evm.runCall({ caller, to, data: hexToBytes(data), gasLimit: 10_000_000n, block: block() })).execResult.returnValue);
    return { address, run, call, read: async (fn, args) => (await run(fn, args)).result };
  }

  return { evm, deploy, contract, setTime: (t) => (timestamp = BigInt(t)) };
}
