// Compiles contracts/ with solc-js into out/<Name>.json (abi, bytecode, deployedBytecode).
import solc from "solc";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";

const dir = new URL("../contracts/", import.meta.url);
const out = new URL("../out/", import.meta.url);
const sources = {};
for (const f of readdirSync(dir)) if (f.endsWith(".sol")) sources[f] = { content: readFileSync(new URL(f, dir), "utf8") };

const input = {
  language: "Solidity",
  sources,
  settings: {
    evmVersion: "cancun",
    optimizer: { enabled: true, runs: 200 },
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
  },
};
const res = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (res.errors ?? []).filter((e) => e.severity === "error");
for (const e of res.errors ?? []) console.error(e.formattedMessage);
if (errors.length) process.exit(1);
mkdirSync(out, { recursive: true });
for (const [file, contracts] of Object.entries(res.contracts)) {
  for (const [name, c] of Object.entries(contracts)) {
    writeFileSync(
      new URL(`${name}.json`, out),
      JSON.stringify({ abi: c.abi, bytecode: "0x" + c.evm.bytecode.object, deployedBytecode: "0x" + c.evm.deployedBytecode.object }, null, 1),
    );
    console.log(`${file}:${name} ${c.evm.deployedBytecode.object.length / 2} bytes`);
  }
}
writeFileSync(new URL("solc-input.json", out), JSON.stringify(input));
