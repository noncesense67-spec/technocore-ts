# READ ME FIRST — what this key is

**Keep this file with the key backup.** It is written for someone who has
forgotten everything about this, because that person is probably you in 2027.

## What you are holding

`agent.ed25519.pem` is an **Ed25519 private key**. It is the identity of an
agent called `nonce-sense` on the Technocore network (technocore.chat), run by
Flop Labs — Arthur Hayes's AI-agent project.

Per Flop Labs' published onboarding, this key is the agent's on-chain identity
and **the address its `$FLOP` airdrop allocation is tied to**. The airdrop was
targeted for Q4 2026; the network's genesis block was expected Q1 2027.

**There is no recovery.** No account, no email, no reset, no support desk. If
this file is lost, the identity and any claim attached to it are gone
permanently. If someone else obtains this file, they *are* the agent.

The matching public identity, which is safe to share:

```
did:key:z6MkpXLQhiDbEgBnBDCaD3vuZgaJGgH8H4YsShNsEw5dqsEw
```

Its registry fingerprint (first 16 hex of SHA-256 of that DID string):

```
531206861d0642d3
```

## Verify this backup is intact

You do not need any special software — just `openssl`, which ships with macOS
and Linux. This prints the public key and confirms the file is a valid Ed25519
key without revealing anything secret:

```bash
openssl pkey -in agent.ed25519.pem -noout -text
```

To confirm it is *the right* key, derive the DID from it. This needs the tooling
in the repo below, or any Ed25519 + base58 library:

```bash
printf '%s' 'did:key:z6MkpXLQhiDbEgBnBDCaD3vuZgaJGgH8H4YsShNsEw5dqsEw' \
  | shasum -a 256 | cut -c1-16
```

That must print `531206861d0642d3`.

## How the key works, if the tooling is gone

The identifier is derived from the key, not registered anywhere, so it can
always be reconstructed:

1. Take the **raw 32-byte** Ed25519 public key.
2. Prepend the multicodec prefix `0xed 0x01` (two bytes — the varint encoding
   of `0xed`, not the single byte).
3. Base58btc-encode those 34 bytes.
4. Prefix with `z`, then with `did:key:`.

Signatures are raw Ed25519 over `<room>|<nonce>|<text>`, encoded base64url
unpadded (86 characters).

## The software that produced this

<https://github.com/noncesense67-spec/technocore-ts> — Apache-2.0.

```bash
git clone https://github.com/noncesense67-spec/technocore-ts
cd technocore-ts && bun install
mkdir -p keys && cp /path/to/agent.ed25519.pem keys/
chmod 600 keys/agent.ed25519.pem
bun run flop whoami     # must print the DID above
bun run flop prove      # regenerates a full verification report
```

If that repository no longer exists, the four steps above are the whole format —
any Ed25519 library reproduces it.

## Rules for handling this file

- Never paste it into a chat, a form, a website, or a support ticket.
- Never post it anywhere on Technocore — every room there is world-readable.
- Nobody legitimate will ever ask you for it. Anyone who does is stealing it.
- Claiming an airdrop should never require *sending* a private key anywhere.
  Signing proves possession without disclosure; that is the entire point of it.

## A warning that was already true in 2026

Flop Labs had issued no token and run no presale, and Arthur Hayes publicly
disowned everything trading under the FLOP name. Any site asking you to
"connect a wallet" or "claim your FLOP" should be assumed fraudulent unless you
have verified it from Flop Labs' own channels first.

## Also in this backup

`agent.x25519.pem` is a separate key used only for encrypted messaging. It is
not tied to the airdrop and can be regenerated — though doing so means
republishing the public half in the agent's registry note.
