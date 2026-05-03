# elgato-plugin-decrypter

Decrypts Elgato Stream Deck plugin packages (`.streamDeckPlugin`) and their encrypted `manifest.json` files. Can also convert the decrypted manifest to a format that works with the **MiraBox Stream Dock** SDK.

## Features

- Decrypt `.streamDeckPlugin` ZIP packages that contain an encrypted `manifest.json`
- Convert decrypted packages to `.sdPlugin` **Stream Dock** format with `--format streamdock`
- Keys are pulled straight out of `StreamDeck.exe` at runtime, so there are no hardcoded keys in this project
- The binary scanner uses a structural approach that keeps working even after Elgato ships an update with a new PCG seed

## Requirements

- [.NET 8 Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Elgato Stream Deck** software installed at `C:\Program Files\Elgato\StreamDeck\StreamDeck.exe`
  - Only needed for decryption. Use `--binary` if yours is installed somewhere else.

## Installation

Clone the repo and build:

```bash
git clone https://github.com/your-username/elgato-plugin-decrypter.git
cd elgato-plugin-decrypter
dotnet build -c Release
```

Or just run it directly without building first:

```bash
dotnet run --project ElgatoDecrypter -- <args>
```

## Usage

```
elgato-decrypter <input> [options]

  input               Path to encrypted manifest.json or .streamDeckPlugin file

Options:
  --output, -o <path> Output file or directory
  --binary, -b <path> Path to StreamDeck.exe for key extraction
  --format, -f <fmt>  Output format: streamdeck (default) | streamdock
```

### Examples

Decrypt a plugin package in-place (overwrites the original file):
```bash
elgato-decrypter plugin.streamDeckPlugin
```

Decrypt a plugin package and write the result to a specific directory:
```bash
elgato-decrypter plugin.streamDeckPlugin -o ./output
```

Decrypt and convert for use with MiraBox Stream Dock (writes a new `.sdPlugin` file alongside the original, named after the bundle ID):
```bash
elgato-decrypter plugin.streamDeckPlugin --format streamdock
```

Not sure why you'd need to do this but you can also decrypt a single manifest to a file:
```bash
elgato-decrypter manifest.json -o decrypted.json
```

---
## Output Formats

| Format       | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `streamdeck` | Default. Writes the decrypted `manifest.json` without any changes.          |
| `streamdock` | Remaps and removes fields to match the [MiraBox Stream Dock SDK](https://sdk.key123.vip/en/guide/manifest.html). |

---

<details>
<summary><strong>How Decryption Works</strong></summary>

> **Fair warning:** This section is purely for the curious. You don't need any of it to use the tool. It's a breakdown of what's actually happening under the hood for people who like knowing how a sausage is made. If that's not you, close this and go decrypt something. Still reading? Then continue below to better understand my sausage. (Heh, wiener jokes are still funny right?)

---

### The Big Picture

Elgato's encrypted `manifest.json` has a few layers to it. It's not a password protected ZIP or anything that simple. This tool works through these layers in three stages:

1. **Find the keys** hidden inside `StreamDeck.exe`
2. **Derive the actual encryption keys** from what was found
3. **Decrypt the manifest** using those keys

---

### Stage 1 - Finding the Keys

Elgato doesn't store the encryption keys as plain text in their app. Instead, they're split up and scattered across the executable, hidden inside low-level CPU instructions that load data into registers.

The tool scans `StreamDeck.exe` for a specific pattern of these instructions that shows up wherever the key material lives. Once found, it reads the raw bytes they point to and pieces the key information back together.

There's also a fallback for when the pattern changes between Elgato updates. If the pattern scan comes up empty, the tool searches for a known constant value that has stayed the same across builds.

---

### Stage 2 - Deriving the Keys

The raw values scraped from the binary aren't usable keys on their own. They have to be calculated from what was found. The process goes like this:

1. A **pseudorandom number generator** (think: a deterministic dice roller seeded with a specific number) is used to shuffle a list of 256 values into a specific order. Elgato uses a slightly non-standard version of this shuffle, which is part of what makes reverse engineering it tricky.

2. That shuffled list is then flipped into its inverse. If the shuffle mapped position 3 to slot 7, the inverse maps 7 back to 3.

3. The final key bytes are produced by combining the inverse lookup with an XOR mask, which is a second layer of scrambling on top of the shuffle.

   XOR works like this: take two bits, if they match the result is 0, if they differ it's 1. Run it again with the same mask and you get the original back. That reversibility is what makes it useful for encryption.

This process runs twice to produce two separate keys, each used for a different part of the decryption.

---

### Stage 3 - Decrypting the Manifest

The encrypted manifest is wrapped in a custom container format. It starts with the text `ELGATO` as a signature, then splits the rest into named sections. Reading it looks like this:

**The header** (the first 32 bytes) tells us the total file size, where the sections start, and a seed number used for the first layer of encryption.

**The section directory** is a small table listing what sections are inside the file (`INFO`, `META`, and `DATA`) and where each one lives. This table is scrambled using a stream cipher, which is a stream of random-looking bytes generated from that seed number, XOR'd byte-by-byte against the real data. Since XOR is reversible, once you have the same seed you can undo it.

**The META section** is also XOR-scrambled, and once unscrambled it contains metadata about the actual encrypted content: how big the data is, how it's split up, and the cryptographic ingredients needed to decrypt it. This metadata is stored in a compact binary format called CBOR (essentially a more efficient, binary version of JSON).

**The key exchange** The metadata contains a randomly generated public key that was created for this specific file at the time it was encrypted. Using a technique called **elliptic curve key exchange**, the tool combines one of the extracted keys with that public key to produce a shared secret, the same one that was used during encryption. From that shared secret, the final AES decryption key is calculated.

> Neither side ever sends the secret. They each plug their own private value into the same mathematical formula and because the math is designed that way, both sides always get the same number out.

**The DATA section** is the actual encrypted manifest, split into chunks. Each chunk first has the same stream-cipher XOR applied to it (using the same seed from the header, offset-adjusted for where the chunk sits in the file), then it is decrypted with **AES-256-GCM** (256-bit key). The GCM mode also verifies the data wasn't tampered with, and each chunk has its own unique IV and authentication tag to prove it's intact. Once all chunks are decrypted and joined back together, you have the original plaintext JSON.

</details>

## License

This project is provided for educational and interoperability purposes.
