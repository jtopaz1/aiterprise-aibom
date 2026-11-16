# Definition bundles

The wheel ships a point-in-time copy of the definition data: the OSV `MAL-` known-malicious
snapshot, the CISA KEV catalog, the AI-package advisory subset, the command and poison rules, and
the rule-quality table. `aiterprise-scan defs status` shows what is in use and where each file
comes from (`wheel`, or an installed `bundle rel_…`).

Newer data arrives as a **signed AIT bundle**, verified before anything is used.

```bash
aiterprise-scan defs update --root-key root.pub     # fetch the latest from SecDB, verify, install
aiterprise-scan defs verify  ./bundle --root-key root.pub
aiterprise-scan defs install ./bundle --root-key root.pub
aiterprise-scan defs rollback                       # previous release, or back to the wheel's data
```

`defs update` asks for the release channel of your SecDB account; `--channel NAME` asks for another
one. `--signing-keys URL` says where `signing-keys.json` is when it is not next to the manifest.

## What is checked

A bundle directory holds `manifest.json`, `signature.minisig`, the archive the manifest names, and
`signing-keys.json` with its own signature. Any failure refuses the bundle and keeps the last good
release.

1. `signing-keys.json` must be signed by the root key, be newer than the list already held (no
   rollback), and not be past its expiry.
2. The manifest signature (minisign, Ed25519) must come from a key in that list and verify over the
   exact bytes.
3. Only then is the manifest parsed: its signing key must be active for its `created_at`; its
   `release_id` must equal `rel_` + SHA-256 of the manifest's canonical JSON; domain, format,
   channel and release must match what was asked for; no downgrade.
4. The archive's size and SHA-256 are checked before it is opened. It is unpacked defensively —
   no absolute paths, no `..`, regular files only, size caps — and every listed file is checked.

Installed releases live in `~/.aiterprise/defs/<release_id>/`; `state.json` names the active one
and is replaced atomically. Each file is re-checked against the installed manifest whenever it is
loaded; a mismatch falls back to the wheel's copy with a warning. `AITERPRISE_DEFS=bundled` ignores
installed bundles entirely.

## The root key

The root public key is not pinned in the scanner yet (SecDB open point O-23). Until it is, pass it
with `--root-key FILE` or `AITERPRISE_ROOT_KEY`. SecDB does not publish an AIT bundle yet either;
`defs update` says so and keeps the current data.

## Compatibility

Signatures are standard [minisign](https://jedisct1.github.io/minisign/) (prehashed `ED`), so a
bundle can also be checked by hand — `root.pub` against `signing-keys.json`, then the signing key
it lists against the manifest:

```bash
minisign -Vm signing-keys.json -p root.pub
minisign -Vm manifest.json -x signature.minisig -P <public key from signing-keys.json>
```

CI checks both directions on every push: the reference `minisign` accepts our signatures, and our
verifier accepts signatures made by `minisign`.
