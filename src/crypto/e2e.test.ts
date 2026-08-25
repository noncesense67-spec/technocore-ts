import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { loadOrCreateX25519 } from "./x25519.ts";
import {
  isEnvelope,
  maxPlaintextBytes,
  open,
  openEnvelope,
  openLine,
  seal,
  sealEnvelope,
  sealLine,
} from "./e2e.ts";

const scratch = () => mkdtempSync(join(tmpdir(), "flop-e2e-"));

describe("AES-GCM primitives", () => {
  test("round-trips", () => {
    const key = new Uint8Array(randomBytes(32));
    const nonce = new Uint8Array(randomBytes(12));
    const plaintext = new Uint8Array(Buffer.from("the quick brown fox"));
    expect(open(key, nonce, seal(key, nonce, plaintext))).toEqual(plaintext);
  });

  test("rejects a tampered ciphertext", () => {
    const key = new Uint8Array(randomBytes(32));
    const nonce = new Uint8Array(randomBytes(12));
    const sealed = seal(key, nonce, new Uint8Array(Buffer.from("authentic")));
    sealed[0] ^= 0xff;
    expect(() => open(key, nonce, sealed)).toThrow();
  });

  test("rejects the wrong key", () => {
    const nonce = new Uint8Array(randomBytes(12));
    const sealed = seal(new Uint8Array(randomBytes(32)), nonce, new Uint8Array(Buffer.from("x")));
    expect(() => open(new Uint8Array(randomBytes(32)), nonce, sealed)).toThrow();
  });
});

describe("handshake envelope (patterns.md §4)", () => {
  test("a sender can reach a recipient using only the published X25519 key", () => {
    const recipient = loadOrCreateX25519(scratch());

    // The sender knows nothing but what the DID note advertises.
    const envelope = sealEnvelope(recipient.rawPublicKey);
    const opened = openEnvelope(recipient, envelope.line);

    expect(opened.roomKey).toEqual(envelope.roomKey);
    expect(opened.room).toBe(envelope.room);
  });

  test("produces the wire format the pattern specifies", () => {
    const recipient = loadOrCreateX25519(scratch());
    const { line } = sealEnvelope(recipient.rawPublicKey);
    const parts = line.split(" ");

    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe("e2e1");
    for (const part of parts.slice(1)) expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(isEnvelope(line)).toBe(true);
  });

  test("mints an unguessable, unlisted p- room by default", () => {
    const recipient = loadOrCreateX25519(scratch());
    const a = sealEnvelope(recipient.rawPublicKey);
    const b = sealEnvelope(recipient.rawPublicKey);

    expect(a.room).toMatch(/^p-[0-9a-f]{32}$/);
    expect(a.room).not.toBe(b.room);
    expect(a.roomKey).not.toEqual(b.roomKey);
  });

  test("a different recipient cannot open it", () => {
    const intended = loadOrCreateX25519(scratch());
    const eavesdropper = loadOrCreateX25519(scratch());
    const { line } = sealEnvelope(intended.rawPublicKey);
    expect(() => openEnvelope(eavesdropper, line)).toThrow();
  });

  test("rejects malformed envelopes without leaking which part failed", () => {
    const recipient = loadOrCreateX25519(scratch());
    expect(() => openEnvelope(recipient, "not an envelope")).toThrow(/not an e2e1/);
    expect(() => openEnvelope(recipient, "e2e1 a b")).toThrow(/not an e2e1/);
    expect(() => openEnvelope(recipient, "e2e1 AAAA BBBB CCCC")).toThrow();
  });

  test("the envelope fits in one message", () => {
    const recipient = loadOrCreateX25519(scratch());
    expect(sealEnvelope(recipient.rawPublicKey).line.length).toBeLessThan(4096);
  });
});

describe("room lines", () => {
  test("round-trip under the shared room key", () => {
    const key = new Uint8Array(randomBytes(32));
    const text = "meet me in the usual namespace";
    expect(openLine(key, sealLine(key, text))).toBe(text);
  });

  test("use the <nonce>.<ct> wire format", () => {
    const key = new Uint8Array(randomBytes(32));
    const line = sealLine(key, "hello");
    expect(line).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  test("are single-line and survive the server's sweep untouched", () => {
    const key = new Uint8Array(randomBytes(32));
    // Even a plaintext full of newlines encrypts to a single safe line.
    const line = sealLine(key, "one\ntwo\tthree\r\nfour");
    expect(line).not.toMatch(/[\p{Cc}\p{Cf}]/u);
    expect(openLine(key, line)).toBe("one\ntwo\tthree\r\nfour");
  });

  test("a fresh nonce per line, so identical plaintexts differ on the wire", () => {
    const key = new Uint8Array(randomBytes(32));
    expect(sealLine(key, "same")).not.toBe(sealLine(key, "same"));
  });

  test("reject a line encrypted under another key", () => {
    const line = sealLine(new Uint8Array(randomBytes(32)), "secret");
    expect(() => openLine(new Uint8Array(randomBytes(32)), line)).toThrow();
  });

  test("reject malformed lines", () => {
    const key = new Uint8Array(randomBytes(32));
    expect(() => openLine(key, "nodot")).toThrow(/malformed/);
    expect(() => openLine(key, "AAAA.BBBB")).toThrow();
  });
});

describe("capacity", () => {
  test("the documented budget actually fits the message cap", () => {
    const key = new Uint8Array(randomBytes(32));
    const max = maxPlaintextBytes(4096);
    expect(sealLine(key, "a".repeat(max)).length).toBeLessThanOrEqual(4096);
    // And one byte more does not.
    expect(sealLine(key, "a".repeat(max + 1)).length).toBeGreaterThan(4096);
  });

  test("a full 2000-char plaintext fits, as patterns.md claims", () => {
    const key = new Uint8Array(randomBytes(32));
    expect(sealLine(key, "x".repeat(2000)).length).toBeLessThan(4096);
  });
});
