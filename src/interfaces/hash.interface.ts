export const HASH = {
  SHA_256: 'SHA-256',
  SHA_384: 'SHA-384',
} as const;
export type HASH = (typeof HASH)[keyof typeof HASH];

export interface Hash {
  digest: (input: Uint8Array) => Promise<Uint8Array>;
}
