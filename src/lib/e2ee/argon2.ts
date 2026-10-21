import { argon2id } from "hash-wasm";
import { utf8 } from "./bytes.ts";

export interface Argon2Params {
  /** Memory in KiB. */
  memorySize: number;
  iterations: number;
  parallelism: number;
  hashLength: number;
}

export const DEFAULT_ARGON2_PARAMS: Readonly<Argon2Params> = Object.freeze({
  memorySize: 32 * 1024,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
});

export function resolveArgon2Params(
  overrides: Partial<Argon2Params> = {},
): Argon2Params {
  const params: Argon2Params = {
    ...DEFAULT_ARGON2_PARAMS,
    ...overrides,
  };

  if (!Number.isInteger(params.memorySize) || params.memorySize < 8) {
    throw new Error("Argon2: memorySize must be an integer >= 8 KiB");
  }
  if (!Number.isInteger(params.iterations) || params.iterations < 1) {
    throw new Error("Argon2: iterations must be an integer >= 1");
  }
  if (!Number.isInteger(params.parallelism) || params.parallelism < 1) {
    throw new Error("Argon2: parallelism must be an integer >= 1");
  }
  if (params.memorySize < 8 * params.parallelism) {
    throw new Error("Argon2: memorySize must be >= 8 * parallelism");
  }
  if (!Number.isInteger(params.hashLength) || params.hashLength < 16) {
    throw new Error("Argon2: hashLength must be an integer >= 16");
  }

  return params;
}

export async function argon2idBytes(
  password: Uint8Array,
  salt: Uint8Array,
  overrides: Partial<Argon2Params> = {},
): Promise<Uint8Array> {
  if (salt.byteLength < 8) {
    throw new Error("Argon2: salt must be at least 8 bytes");
  }

  const params = resolveArgon2Params(overrides);
  const output = await argon2id({
    password,
    salt,
    iterations: params.iterations,
    parallelism: params.parallelism,
    memorySize: params.memorySize,
    hashLength: params.hashLength,
    outputType: "binary",
  });

  return new Uint8Array(output);
}

export async function deriveRootKey(
  passphrase: string,
  kdfSalt: Uint8Array,
  overrides: Partial<Argon2Params> = {},
): Promise<Uint8Array> {
  const root = await argon2idBytes(utf8(passphrase), kdfSalt, overrides);
  if (root.byteLength !== 32) {
    throw new Error("Argon2: root key must be 32 bytes");
  }
  return root;
}
