import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const reference = process.argv[2] ?? "/tmp/opencode/research/rci-tools";
const pin = "1486b62af803b816a570e44a67c14f6c30bc4904";
assert.equal(execFileSync("git", ["-C", reference, "rev-parse", "HEAD"], {
  encoding: "utf8", env: { ...process.env, GIT_MASTER: "1" },
}).trim(), pin);
const requireReference = createRequire(`${reference}/package.json`);
const { argon2id } = requireReference("hash-wasm");
const prefix = `${reference}/packages/core/src/session-manager/auth-protocol/x-ndw4-interactive/`;
const { hmacSha3_512, sha3_512, encodeBase64 } = await import(pathToFileURL(`${prefix}ndw4-auth.utils.ts`).href);
const { NDW4_CLIENT_KEY, NDW4_SERVER_KEY, NDW4_HASH_LENGTH, NDW4_PARALLELISM } = await import(pathToFileURL(`${prefix}ndw4-auth.constants.ts`).href);
const login = "admin";
const password = "vector-password";
const salt = Uint8Array.from({ length: 16 }, (_, index) => index);
const nonce = encodeBase64(Uint8Array.from({ length: 16 }, (_, index) => index + 16));
const combinedNonce = `${nonce}${encodeBase64(Uint8Array.from({ length: 16 }, (_, index) => index + 32))}`;
const iter = "02";
const memcost = "0064";
const message = `login1=${login},nonce1=${nonce};iter2=${iter},memcost2=${memcost},nonce2=${combinedNonce},salt2=${encodeBase64(salt)};login3=${login},nonce3=${combinedNonce}`;
const salted = await argon2id({ password, salt, iterations: Number(iter), memorySize: Number(memcost), parallelism: NDW4_PARALLELISM, hashLength: NDW4_HASH_LENGTH, outputType: "binary" });
const client = await hmacSha3_512(salted, NDW4_CLIENT_KEY);
const stored = await sha3_512(client);
const server = await hmacSha3_512(salted, NDW4_SERVER_KEY);
const signature = encodeBase64(await hmacSha3_512(server, message));
const proof = async (text) => {
  const mask = await hmacSha3_512(stored, text);
  assert.equal(mask.length, client.length);
  return encodeBase64(Uint8Array.from(client, (byte, index) => byte ^ mask.at(index)));
};
const vector = {
  source: `Eralde/rci-tools@${pin}`, hashWasm: "4.12.0", login, password,
  salt: encodeBase64(salt), nonce, combinedNonce, iter, memcost, message,
  salted: encodeBase64(salted), client: encodeBase64(client), stored: encodeBase64(stored),
  server: encodeBase64(server), proof: await proof(message), signature,
  signatureProof: await proof(`${message};signature4=${signature}`),
};
await writeFile(new URL("../../tests/vectors/ndw4.json", import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
