# ATP CLI — Command Flow Charts

Each command's operations, decision points, failure modes, and success outcomes.

---

## identity create

```mermaid
flowchart TD
    A[atp identity create] --> B{--private-key?}
    B -->|Yes| C[Load private key from file]
    B -->|No| D[Generate Ed25519 keypair]
    C --> C1{--public-key?}
    C1 -->|Yes| C2[Load public key]
    C2 --> C3{Keys match?}
    C3 -->|No| FAIL1[EXIT 1: public key does not match private key]
    C3 -->|Yes| C4[Derive fingerprint]
    C1 -->|No| C4
    D --> D1[Save keypair to ~/.atp/keys/]
    D1 --> C4
    C4 --> E{Name valid? ASCII 1-64 chars}
    E -->|No| FAIL2[EXIT 1: invalid name]
    E -->|Yes| F[Build identity document]
    F --> G[Validate timestamp]
    G -->|Future/too old| FAIL3[EXIT 1: timestamp out of range]
    G -->|OK| H[Collect metadata --meta/--link/--wallet/--key-ref]
    H --> I[Schema validation]
    I -->|Fail| FAIL4[EXIT 1: schema validation failed]
    I -->|Pass| J[Sign document]
    J --> K{--output?}
    K -->|Yes| L[Write to file]
    K -->|No| M[Print to stdout]
    L --> OK1[✓ Identity written]
    M --> OK1
```

## identity show

```mermaid
flowchart TD
    A[atp identity show file] --> B[Read file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C[Parse JSON]
    C -->|Invalid JSON| FAIL2[EXIT 1: parse error]
    C -->|OK| D[Compute fingerprint from k.p]
    D --> E[Display: name, version, type, key, fingerprint, metadata, timestamp, signature]
    E --> OK1[✓ Identity displayed]
```

## identity inscribe

```mermaid
flowchart TD
    A[atp identity inscribe] --> B[Read document file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C{Valid JSON?}
    C -->|Yes| D[content-type = application/atp.v1+json]
    C -->|No| E[content-type = application/atp.v1+cbor]
    D --> F[Build inscription envelope]
    E --> F
    F --> G[Output envelope hex + instructions]
    G --> OK1[✓ Envelope ready]
```

---

## attest

```mermaid
flowchart TD
    A[atp attest fingerprint] --> B[Read --from identity file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C[Parse identity, compute attestor fingerprint]
    C --> D[Build attestation document]
    D --> E[Validate timestamp]
    E -->|Out of range| FAIL2[EXIT 1: timestamp out of range]
    E -->|OK| F[Add optional: --stake, --context]
    F --> G[Schema validation]
    G -->|Fail| FAIL3[EXIT 1: schema validation failed]
    G -->|Pass| H{--private-key?}
    H -->|Yes| I[Load private key from file]
    H -->|No| J[Load private key by identity file]
    I --> K[Sign document]
    J --> K
    K --> L{--output?}
    L -->|Yes| M[Write to file]
    L -->|No| N[Print to stdout]
    M --> OK1[✓ Attestation created]
    N --> OK1
```

---

## att-revoke

```mermaid
flowchart TD
    A[atp att-revoke txid] --> B{TXID valid? 64 hex chars}
    B -->|No| FAIL1[EXIT 1: TXID must be 64 hex characters]
    B -->|Yes| C[Read --from identity file]
    C -->|ENOENT| FAIL2[EXIT 1: file not found]
    C -->|OK| D[Build att-revoke document]
    D --> E[Validate timestamp]
    E -->|Out of range| FAIL3[EXIT 1: timestamp out of range]
    E -->|OK| F[Schema validation]
    F -->|Fail| FAIL4[EXIT 1: schema validation failed]
    F -->|Pass| G{--private-key?}
    G -->|Yes| H[Load private key from file]
    G -->|No| I[Load private key by identity file]
    H --> J[Sign document]
    I --> J
    J --> K{--output?}
    K -->|Yes| L[Write to file]
    K -->|No| M[Print to stdout]
    L --> OK1[✓ Attestation revocation created]
    M --> OK1
```

---

## heartbeat

```mermaid
flowchart TD
    A[atp heartbeat] --> B[Read --from identity file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C[Parse identity, compute fingerprint]
    C --> D[Build heartbeat document with --seq and --txid]
    D --> E[Validate timestamp]
    E -->|Out of range| FAIL2[EXIT 1: timestamp out of range]
    E -->|OK| F[Add optional --msg]
    F --> G[Schema validation]
    G -->|Fail| FAIL3[EXIT 1: schema validation failed]
    G -->|Pass| H{--private-key?}
    H -->|Yes| I[Load private key from file]
    H -->|No| J[Load private key by identity file]
    I --> K[Sign document]
    J --> K
    K --> L{--output?}
    L -->|Yes| M[Write to file]
    L -->|No| N[Print to stdout]
    M --> OK1[✓ Heartbeat created]
    N --> OK1
```

---

## supersede

```mermaid
flowchart TD
    A[atp supersede] --> B[Read --old identity file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C[Parse old identity, compute old fingerprint]
    C --> D{reason?}
    D -->|metadata-update| E[Reuse old key as new key]
    D -->|key-rotation / algorithm-upgrade / key-compromised| F{--new-private-key?}
    F -->|Yes| G[Load new private key from file]
    F -->|No| H[Generate new keypair]
    E --> I[Validate name]
    G --> I
    H --> I
    I -->|Invalid| FAIL2[EXIT 1: Name must be 1-64 ASCII characters]
    I -->|Valid| J[Collect metadata tuples]
    J --> K[Build supersession document with target ref]
    K --> L[Validate timestamp]
    L -->|Out of range| FAIL3[EXIT 1: timestamp out of range]
    L -->|OK| M[Schema validation]
    M -->|Fail| FAIL4[EXIT 1: schema validation failed]
    M -->|Pass| N{--old-private-key or --private-key?}
    N -->|Yes| O[Load old private key from file]
    N -->|No| P[Load old private key by identity file]
    O --> Q[Sign with old key]
    P --> Q
    Q --> R[Sign with new key]
    R --> S["Set s = [oldSig, newSig]"]
    S --> T{--output?}
    T -->|Yes| U[Write to file]
    T -->|No| V[Print to stdout]
    U --> OK1[✓ Supersession created]
    V --> OK1
```

---

## revoke

```mermaid
flowchart TD
    A[atp revoke] --> B[Read --identity file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C[Parse identity, compute target fingerprint]
    C --> D[Build revocation document with --txid and --reason]
    D --> E[Validate timestamp]
    E -->|Out of range| FAIL2[EXIT 1: timestamp out of range]
    E -->|OK| F[Schema validation]
    F -->|Fail| FAIL3[EXIT 1: schema validation failed]
    F -->|Pass| G{Key source?}
    G -->|--private-key| H[Load from private key file]
    G -->|--key| I[Load by key file path]
    G -->|default| J[Load by identity file]
    H --> K[Sign document]
    I --> K
    J --> K
    K --> L{--output?}
    L -->|Yes| M[Write to file]
    L -->|No| N[Print to stdout]
    M --> OK1[✓ Revocation created]
    N --> OK1
```

---

## receipt create

```mermaid
flowchart TD
    A[atp receipt create] --> B[Read --from identity file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C[Parse identity, compute initiator fingerprint]
    C --> D[Build receipt with two parties, exchange details]
    D --> E[Validate timestamp]
    E -->|Out of range| FAIL2[EXIT 1: timestamp out of range]
    E -->|OK| F[Schema validation]
    F -->|Fail| FAIL3[EXIT 1: schema validation failed]
    F -->|Pass| G{--private-key?}
    G -->|Yes| H[Load private key from file]
    G -->|No| I[Load private key by identity file]
    H --> J[Sign document]
    I --> J
    J --> K["Set s = [initiatorSig, '<awaiting-counterparty-signature>']"]
    K --> L{--output?}
    L -->|Yes| M[Write to file]
    L -->|No| N[Print to stdout]
    M --> OK1[✓ Partial receipt — send to counterparty]
    N --> OK1
```

## receipt countersign

```mermaid
flowchart TD
    A[atp receipt countersign] --> B[Read --receipt file]
    B -->|ENOENT| FAIL1[EXIT 1: file not found]
    B -->|OK| C{Valid receipt structure?}
    C -->|No| FAIL2[EXIT 1: not a valid receipt document]
    C -->|Yes| D[Read --identity file]
    D --> E[Compute own fingerprint]
    E --> F{Fingerprint in receipt parties?}
    F -->|No| FAIL3[EXIT 1: fingerprint not found in receipt parties]
    F -->|Yes| G[For each other party:]
    G --> H{Signature present?}
    H -->|No| FAIL4[EXIT 1: party has not signed yet]
    H -->|Yes| I[Resolve identity via RPC]
    I -->|RPC error| FAIL5[EXIT 1: could not resolve identity — refusing to countersign]
    I -->|OK| J{Fingerprint matches?}
    J -->|No| FAIL6[EXIT 1: fingerprint mismatch]
    J -->|Yes| K[Verify signature]
    K -->|Invalid| FAIL7[EXIT 1: signature INVALID — refusing to countersign]
    K -->|Valid| L[✓ Other party verified]
    L --> M{--private-key?}
    M -->|Yes| N[Load private key from file]
    M -->|No| O[Load private key by identity file]
    N --> P[Sign document]
    O --> P
    P --> Q{--output?}
    Q -->|Yes| R[Write to file]
    Q -->|No| S[Print to stdout]
    R --> OK1[✓ Receipt countersigned]
    S --> OK1
```

---

## verify

```mermaid
flowchart TD
    A[atp verify source] --> B{Source is TXID? 64 hex}
    B -->|Yes| C[Fetch via Bitcoin RPC]
    C -->|RPC error| FAIL1[EXIT 1: RPC connection/fetch failed]
    C -->|OK| D{Witness data?}
    D -->|No| FAIL2[EXIT 1: no witness data]
    D -->|Yes| E[Extract inscription from witness]
    E -->|No inscription| FAIL3[EXIT 1: no inscription found]
    E -->|OK| F[Decode JSON or CBOR]
    B -->|No| G[Read as local file]
    G -->|ENOENT| FAIL4[EXIT 1: file not found]
    G -->|OK| F
    F --> H[Schema validation using parsed result]
    H -->|Fail| FAIL5[EXIT 1: schema validation failed]
    H -->|Pass| I{Version 1.0?}
    I -->|No| FAIL6[EXIT 1: unsupported version]
    I -->|Yes| J[Validate optional timestamp]
    J --> K{Document type?}
```

### verify — by document type

```mermaid
flowchart TD
    K{Document type?} --> ID[t = id]
    K --> ATT[t = att]
    K --> HB[t = hb]
    K --> SUP[t = super]
    K --> REV[t = revoke]
    K --> AR[t = att-revoke]
    K --> RCPT[t = rcpt]
    K --> UNK[unknown]
    UNK --> FAIL[EXIT 1: unknown document type]

    ID --> ID1[Extract pubkey from k field]
    ID1 --> ID2[Verify self-signature]
    ID2 -->|Invalid| FAILSIG[EXIT 1: ✗ INVALID]
    ID2 -->|Valid| PASS[✓ VALID]

    ATT --> ATT1[Resolve attestor identity via ref — RPC]
    ATT1 -->|Error| FAILERR[EXIT 1: could not resolve]
    ATT1 -->|OK| ATT2{Fingerprint match?}
    ATT2 -->|No| FAILFP[EXIT 1: fingerprint mismatch]
    ATT2 -->|Yes| ATT3[Verify signature]
    ATT3 -->|Invalid| FAILSIG
    ATT3 -->|Valid| PASS

    HB --> HB1[Resolve identity via ref — RPC]
    HB1 -->|Error| FAILERR
    HB1 -->|OK| HB2{Fingerprint match?}
    HB2 -->|No| FAILFP
    HB2 -->|Yes| HB3[Verify signature]
    HB3 -->|Invalid| FAILSIG
    HB3 -->|Valid| PASS

    SUP --> SUP1[Resolve old identity via target.ref — RPC]
    SUP1 -->|Error| FAILERR
    SUP1 -->|OK| SUP2{Target fingerprint match?}
    SUP2 -->|No| FAILFP
    SUP2 -->|Yes| SUP3["Verify s[0] with old key"]
    SUP3 -->|Invalid| FAILSIG
    SUP3 -->|Valid| SUP4["Verify s[1] with new key"]
    SUP4 -->|Invalid| FAILSIG
    SUP4 -->|Valid| PASS

    REV --> REV1[Resolve target identity via target.ref — RPC]
    REV1 -->|Error| FAILERR
    REV1 -->|OK| REV2[Verify signature]
    REV2 -->|Invalid| FAILSIG
    REV2 -->|Valid| PASS

    AR --> AR1[Fetch attestation via ref — RPC]
    AR1 -->|Error| FAILERR
    AR1 -->|OK| AR2{t = att?}
    AR2 -->|No| FAILTYPE[EXIT 1: expected att]
    AR2 -->|Yes| AR3{--explorer-url?}
    AR3 -->|Yes| AR4[Walk supersession chain via explorer]
    AR4 --> AR5[Verify each chain TXID on-chain via RPC]
    AR5 --> AR6[Try signature against each chain key]
    AR6 -->|No match| FAILCHAIN[EXIT 1: no chain key matches]
    AR6 -->|Match| PASS
    AR3 -->|No| AR7[Resolve original attestor key via RPC]
    AR7 --> AR8[Verify signature]
    AR8 -->|Invalid| FAILNOEXP["EXIT 1: does not match + requires --explorer-url"]
    AR8 -->|Valid| PASS

    RCPT --> RCPT1[For each party with signature:]
    RCPT1 --> RCPT2[Resolve identity via ref — RPC]
    RCPT2 -->|Error| FAILERR
    RCPT2 -->|OK| RCPT3{Fingerprint match?}
    RCPT3 -->|No| FAILFP
    RCPT3 -->|Yes| RCPT4[Verify party signature]
    RCPT4 -->|Invalid| FAILSIG
    RCPT4 -->|Valid| RCPT5{More parties?}
    RCPT5 -->|Yes| RCPT1
    RCPT5 -->|No| PASS

    PASS --> WARN{--explorer-url used?}
    WARN -->|No| W1["⚠ Chain state NOT checked"]
    WARN -->|Yes| W2["✓ Chain state verified via explorer"]
```

---

## key import

```mermaid
flowchart TD
    A[atp key import] --> B[Load private key from --private-key file]
    B -->|Invalid format| FAIL1[EXIT 1: cannot detect key format]
    B -->|Wrong size| FAIL2[EXIT 1: key is N bytes, expected 32]
    B -->|OK| C{Key already in store?}
    C -->|Yes, no --force| FAIL3[EXIT 1: key already exists, use --force]
    C -->|Yes, --force| D[Overwrite]
    C -->|No| D
    D --> E[Save to ~/.atp/keys/]
    E --> OK1[✓ Print fingerprint]
```

## key list

```mermaid
flowchart TD
    A[atp key list] --> B[Ensure ~/.atp/keys/ exists]
    B --> C[Read directory]
    C --> D{Any .json files?}
    D -->|No| E[Print: No keys found]
    D -->|Yes| F[For each key file: print fingerprint, type, path]
    F --> OK1[✓ Keys listed]
```

## key export

```mermaid
flowchart TD
    A[atp key export fingerprint] --> B[Read ~/.atp/keys/fingerprint.json]
    B -->|ENOENT| FAIL1[EXIT 1: key not found]
    B -->|OK| C{--public-only?}
    C -->|Yes| D[Extract public key only]
    C -->|No| E[Include private key]
    D --> F{--format?}
    E --> F
    F -->|json| G[Print JSON]
    F -->|hex| H[Print hex]
    F -->|base64url| I[Print base64url]
    F -->|unknown| FAIL2[EXIT 1: unknown format]
    G --> OK1[✓ Key exported]
    H --> OK1
    I --> OK1
```

## key delete

```mermaid
flowchart TD
    A[atp key delete fingerprint] --> B{--force?}
    B -->|No| FAIL1[EXIT 1: deletion irreversible, use --force]
    B -->|Yes| C[Delete ~/.atp/keys/fingerprint.json]
    C -->|ENOENT| FAIL2[EXIT 1: key not found]
    C -->|OK| OK1[✓ Key deleted]
```

---

## Common Failure Modes

All commands share these failure patterns:

| Failure | Trigger | Exit Code |
|---------|---------|-----------|
| File not found | Any `--from`, `--identity`, `--file`, `--receipt` pointing to missing file | 1 |
| Invalid JSON | Corrupted or non-JSON identity file | 1 |
| Key load failure | Wrong format, wrong size, missing key file | 1 |
| Schema validation | Document doesn't match ATP schema (missing fields, wrong types) | 1 |
| Timestamp out of range | `ts` too far in the past or future | 1 |
| RPC connection failure | Bitcoin node unreachable or wrong credentials | 1 |
| Signature verification | Cryptographic signature doesn't match public key + document | 1 |
| TXID format | Non-hex or wrong length for transaction IDs | 1 |

**Principle:** All failures exit with code 1 and a descriptive error to stderr. No silent failures, no warnings-and-proceed. AI agents need unambiguous failure signals.
