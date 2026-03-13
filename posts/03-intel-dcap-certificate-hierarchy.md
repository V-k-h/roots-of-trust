# Roots of Trust, Part III: Intel DCAP Certificate Hierarchy

*X.509, TEE Attestation, and Verifiable Infrastructure*

---

Intel's [Data Center Attestation Primitives (DCAP)](https://download.01.org/intel-sgx/sgx-dcap/) is the attestation framework for[Intel SGX](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html) (Software Guard Extensions) and [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) (Trust Domain Extensions) in data center environments. Unlike the older [EPID](https://en.wikipedia.org/wiki/Enhanced_Privacy_ID) model—which relied on Intel's attestation service as a central verifier—DCAP enables fully decentralized verification. Anyone with the right collateral can verify a quote without contacting Intel.

This makes DCAP the natural fit for blockchain applications. But DCAP verification requires understanding a specific certificate hierarchy, proprietary extensions, and a collateral system that doesn't map cleanly to standard PKI patterns.

This post is the technical reference. We'll cover the certificate chain structure, [PCK](https://download.01.org/intel-sgx/sgx-dcap/) certificate extensions, FMSPC encoding, TCB status evaluation, and how this maps to on-chain verification—including Solidity snippets and TDX-specific differences throughout.

---

## DCAP Overview

### DCAP vs EPID

Intel has shipped two attestation models:

| Aspect | EPID (legacy) | DCAP (current) |
|--------|---------------|----------------|
| **Verification** | Intel Attestation Service (IAS) | Anyone with collateral |
| **Privacy** | Group signatures (unlinkable) | Standard ECDSA (linkable per-platform) |
| **Infrastructure** | Requires Intel online service | Fully offline-capable |
| **Use case** | Consumer devices, privacy-sensitive | Data centers, blockchain |

EPID used group signatures to provide unlinkability—multiple attestations from the same CPU couldn't be correlated. DCAP trades this for decentralization: each CPU has a unique Provisioning Certification Key (PCK), and anyone can verify quotes against the certificate chain.

For blockchain applications, DCAP's properties are essential. You can't build trustless on-chain verification if verification requires calling Intel's API.

### SGX vs TDX in DCAP

DCAP supports both SGX and TDX. The certificate hierarchy and collateral system are shared, but quote structures differ:

| Aspect | SGX | TDX |
|--------|-----|-----|
| **Isolation unit** | Enclave (process-level) | Trust Domain (VM-level) |
| **Quote version** | Version 3 | Version 4 |
| **Measurement** | MRENCLAVE (code hash) | MRTD (TD measurement) + RTMR (runtime) |
| **Report body** | 384 bytes | 584 bytes (includes TD-specific fields) |
| **TCB components** | SGX TCB (16 SVNs) | TDX TCB (includes TDX Module SVN) |

The verification pipeline is structurally identical. We'll note TDX-specific differences where they impact implementation.

---

## The Certificate Hierarchy

The PCK certificate is part of the X.509 certificate hierarchy, but the attestation quote itself is signed by a QE attestation key whose trust is
established through that collateral chain. In other words, the certificate chain certifies the key; the key signs the quote.

DCAP uses a three-level certificate hierarchy anchored to Intel's root CA.

```mermaid
flowchart TD
    Root["Intel SGX Root CA<br>• Self-signed, ECDSA P-256<br>• Validity: 2016–2049<br>• Shared trust anchor for SGX and TDX collateral"]
    
    subgraph Intermediate["Intermediate CA"]
        PlatformCA["Intel SGX PCK Platform CA<br>(multi-package platforms)"]
        ProcessorCA["Intel SGX PCK Processor CA<br>(single-package platforms)"]
    end
    
    PCK["PCK Certificate<br>• ECDSA P-256<br>• Platform-specific<br>• Encodes FMSPC and TCB-related extensions"]
    
    AK["QE Attestation Key<br>• Certified via PCK collateral"]
    
    Quote["Attestation Quote<br>• Signed by QE attestation key<br>• Contains measurement and report data"]
    
    Root -->|signs| PlatformCA
    Root -->|signs| ProcessorCA
    PlatformCA -->|signs| PCK
    ProcessorCA -->|signs| PCK
    PCK -->|certifies| AK
    AK -->|signs| Quote
    
    style Root fill:#3498db,color:#fff
    style PCK fill:#9b59b6,color:#fff
    style Quote fill:#27ae60,color:#fff
```

### Certificate Retrieval

PCK certificates are retrieved from Intel's Provisioning Certification Service (PCS) using platform-specific identifiers. The flow:

1. Platform registers with Intel during provisioning
2. Intel issues PCK certificate based on CPU identity and current TCB
3. Certificate cached locally (PCCS) or fetched on-demand
4. Verifier obtains certificate as part of collateral

For on-chain verification, the collateral (including PCK cert) must be available on-chain or passed as calldata.

---

## PCK Certificate Deep Dive

The PCK certificate is a standard X.509v3 certificate with Intel-specific extensions. These extensions encode platform identity and TCB information that verifiers must parse and evaluate.

### Standard Fields

| Field | Value |
|-------|-------|
| Version | v3 |
| Serial Number | Unique per certificate |
| Issuer | CN=Intel SGX PCK Platform CA or Processor CA |
| Validity | ~5 years from issuance |
| Subject | CN=Intel SGX PCK Certificate |
| Public Key | ECDSA P-256 |
| Signature Algorithm | ecdsa-with-SHA256 |

### Intel-Specific Extensions

Intel defines extensions under the OID arc `1.2.840.113741.1.13.1`. These are non-critical extensions.

```mermaid
flowchart TD
    RootOID["Intel SGX Extension OID<br>1.2.840.113741.1.13.1"]
    
    PPID[".1 PPID<br>16 bytes, encrypted<br>Platform Provisioning ID"]
    TCB[".2 TCB<br>16 SGX SVN components<br>+ PCESVN<br>TDX: additional components"]
    PCEID[".3 PCE-ID<br>2 bytes<br>Provisioning Cert Enclave ID"]
    FMSPC[".4 FMSPC<br>6 bytes<br>Family-Model-Stepping-Platform-CustomSKU"]
    SGXType[".5 SGX Type<br>0 = Standard<br>1 = Scalable<br>2 = Scalable + Integrity"]

    RootOID --> PPID
    RootOID --> TCB
    RootOID --> PCEID
    RootOID --> FMSPC
    RootOID --> SGXType
```

### Parsing PCK Extensions in Solidity

The following demonstrates parsing PCK certificate extensions. This is architecturally similar to Automata's approach.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title PCK Certificate Extension Parser
/// @notice Extracts Intel SGX/TDX specific extensions from PCK certificates

library PCKExtensionParser {
    // Intel SGX Extension OIDs
    // 1.2.840.113741.1.13.1 = 06 09 2A 86 48 86 F8 4D 01 0D 01
    bytes constant SGX_EXTENSION_OID = hex"2A8648864D010D01";
    
    // Sub-OIDs (appended to base)
    uint8 constant OID_PPID = 1;
    uint8 constant OID_TCB = 2;
    uint8 constant OID_PCEID = 3;
    uint8 constant OID_FMSPC = 4;
    uint8 constant OID_SGX_TYPE = 5;
    
    struct PCKExtensions {
        bytes6 fmspc;
        bytes2 pceId;
        uint8 sgxType;
        TCBLevels tcb;
    }
    
    struct TCBLevels {
        uint8[16] sgxTcbCompSvn;  // 16 component SVNs
        uint16 pcesvn;
        // For TDX: additional fields
        uint8[16] tdxTcbCompSvn;  // TDX-specific
        bool isTdx;
    }
    
    /// @notice Parse extensions from DER-encoded PCK certificate
    function parseExtensions(bytes memory certDer) 
        internal 
        pure 
        returns (PCKExtensions memory ext) 
    {
        // Find extensions sequence (context tag [3])
        uint256 extOffset = findExtensionsOffset(certDer);
        require(extOffset > 0, "Extensions not found");
        
        // Iterate through extensions
        uint256 pos = extOffset;
        while (pos < certDer.length) {
            (bytes memory oid, bytes memory value, uint256 nextPos) = 
                parseExtension(certDer, pos);
            
            if (nextPos == 0) break;
            
            // Check if this is an Intel SGX extension
            if (startsWith(oid, SGX_EXTENSION_OID)) {
                uint8 subOid = uint8(oid[oid.length - 1]);
                parseIntelExtension(subOid, value, ext);
            }
            
            pos = nextPos;
        }
    }
    
    // Helper functions (implementations omitted for brevity)
    function findExtensionsOffset(bytes memory der) 
        internal pure returns (uint256);
    function parseExtension(bytes memory der, uint256 offset) 
        internal pure returns (bytes memory oid, bytes memory value, uint256 nextPos);
    function startsWith(bytes memory data, bytes memory prefix) 
        internal pure returns (bool);
}
```

---

## FMSPC and Platform Identification

FMSPC (Family-Model-Stepping-Platform-CustomSKU) is the 6-byte platform identifier Intel uses to map a platform certificate to the appropriate TCBInfo collateral. Understanding FMSPC is essential for collateral retrieval and verification.

### FMSPC Structure

```mermaid
flowchart LR
    subgraph FMSPC["FMSPC (6 bytes)"]
        B01["Bytes 0-1<br>Family + Model<br>e.g., 0x00806 = Ice Lake"]
        B2["Byte 2<br>Stepping <br>e.g., 0x0C = C0"]
        B3["Byte 3<br>Platform Type"]
        B45["Bytes 4-5<br>Custom SKU<br>Reserved"]
    end
    
    B01 --> B2 --> B3 --> B45
```

**Example FMSPC values:**
These examples are illustrative; in practice, the verifier treats FMSPC as an opaque 6-byte platform identifier used to select the correct TCBInfo collateral.
- `00906ED500FF`: Xeon Scalable (Ice Lake)
- `00806C0100FF`: Xeon E (Coffee Lake)
- `00A06F0500FF`: Xeon Scalable 4th Gen (Sapphire Rapids)

### Why FMSPC Matters

1. **TCBInfo lookup:** Each FMSPC has a corresponding TCBInfo JSON that defines valid TCB levels for that platform
2. **Collateral matching:** The verifier must fetch TCBInfo matching the quote's FMSPC
3. **Platform differentiation:** Two CPUs with same microarchitecture but different FMSPC may have different TCB recovery schedules

---

## TCBInfo Structure

TCBInfo is a signed JSON document from Intel that defines the security levels for a specific platform (identified by FMSPC). The verifier compares the quote's TCB against this document to determine the platform's security status.

### TCBInfo Schema

```mermaid
flowchart TD
    Header["TCBInfo Header<br>• version<br>• issueDate / nextUpdate<br>• fmspc / pceId<br>• tcbType"]
    
    TDXModule["TDX Module Info (TDX only)<br>• mrsigner<br>• attributes + mask"]
    
    Levels["tcbLevels[]<br>ordered highest-first"]
    
    TCB["tcb<br>• sgxtcbcomponents[16]<br>• pcesvn<br>• tdxtcbcomponents (TDX)"]
    Status["tcbStatus<br>UpToDate / OutOfDate / Revoked / ..."]
    Advisory["advisoryIDs[]<br>INTEL-SA-*"]
    
    Sig["signature<br>ECDSA over tcbInfo"]
    
    Header --> TDXModule
    Header --> Levels
    Levels --> TCB
    Levels --> Status
    Levels --> Advisory
    Header --> Sig
```

### TCB Status Values

| Status | Meaning | Recommended Action |
|--------|---------|-------------------|
| `UpToDate` | Platform TCB is current | Accept |
| `SWHardeningNeeded` | Mitigations required in software | Accept with advisory check |
| `ConfigurationNeeded` | Platform config needs update | Policy decision |
| `ConfigurationAndSWHardeningNeeded` | Both above | Policy decision |
| `OutOfDate` | TCB is outdated | Reject or accept with risk |
| `OutOfDateConfigurationNeeded` | Outdated + config issue | Reject |
| `Revoked` | Platform compromised | Reject |

### TCB Level Matching Algorithm

The verifier must find the highest TCB level where the platform's SVNs meet or exceed all component requirements:

```solidity
/// @title TCB Level Evaluator
/// @notice Determines TCB status based on platform SVNs and TCBInfo

library TCBEvaluator {
    struct TCBLevel {
        uint8[16] sgxTcbCompSvn;
        uint16 pcesvn;
        uint8[16] tdxTcbCompSvn;  // Empty for SGX-only
        string status;
    }
    
    /// @notice Find matching TCB level for platform
    function evaluateTcb(
        PCKExtensionParser.TCBLevels memory platformTcb,
        TCBLevel[] memory tcbLevels
    ) internal pure returns (string memory status, uint256 levelIndex) {
        
        for (uint256 i = 0; i < tcbLevels.length; i++) {
            if (tcbMeetsLevel(platformTcb, tcbLevels[i])) {
                return (tcbLevels[i].status, i);
            }
        }
        
        revert("TCB below minimum known level");
    }
    
    /// @notice Check if platform TCB meets or exceeds a level
    function tcbMeetsLevel(
        PCKExtensionParser.TCBLevels memory platform,
        TCBLevel memory level
    ) internal pure returns (bool) {
        // All SGX components must meet or exceed
        for (uint8 i = 0; i < 16; i++) {
            if (platform.sgxTcbCompSvn[i] < level.sgxTcbCompSvn[i]) {
                return false;
            }
        }
        
        // PCESVN must meet or exceed
        if (platform.pcesvn < level.pcesvn) {
            return false;
        }
        
        // For TDX: also check TDX components
        if (platform.isTdx) {
            for (uint8 i = 0; i < 16; i++) {
                if (platform.tdxTcbCompSvn[i] < level.tdxTcbCompSvn[i]) {
                    return false;
                }
            }
        }
        
        return true;
    }
}
```

---

## Quoting Enclave Identity

The QE (Quoting Enclave) is Intel's signed enclave that transforms local reports into verifiable quotes. Verifiers must validate that the QE itself is legitimate.

### QEIdentity Structure

QEIdentity is Intel-signed collateral that specifies which Quoting Enclave identities are valid for a given attestation model and TCB state.
```mermaid
flowchart LR
    subgraph QEIdentity["QEIdentity JSON"]
        Header["id: 'QE' or 'TD_QE'<br>version: 2<br>issueDate, nextUpdate"]
        
        Identity["Identity Fields:<br>• mrsigner (expected QE signer)<br>• isvprodid (product ID)<br>• tcbLevels[]"]
        
        Attrs["Attributes:<br>• attributes (expected flags)<br>• attributesMask (which bits matter)<br>• miscselect / miscselectMask"]
        
        Sig["signature"]
    end
    
    Header --> Identity --> Attrs --> Sig
```

### QE Identity Verification

```solidity
/// @title QE Identity Verifier
/// @notice Validates Quoting Enclave identity from quote

library QEIdentityVerifier {
    struct QEIdentity {
        bytes32 mrsigner;
        uint16 isvprodid;
        uint16 minIsvsvn;
        bytes16 attributes;
        bytes16 attributesMask;
        bytes4 miscselect;
        bytes4 miscselectMask;
    }
    
    /// @notice Verify QE report matches expected identity
    function verifyQEIdentity(
        bytes memory qeReport,
        QEIdentity memory expectedIdentity
    ) internal pure returns (bool) {
        // Extract fields from QE report
        bytes32 qeMrsigner = extractMrsigner(qeReport);
        uint16 qeIsvprodid = extractIsvprodid(qeReport);
        uint16 qeIsvsvn = extractIsvsvn(qeReport);
        bytes16 qeAttributes = extractAttributes(qeReport);
        bytes4 qeMiscselect = extractMiscselect(qeReport);
        
        // Verify MRSIGNER matches
        if (qeMrsigner != expectedIdentity.mrsigner) {
            return false;
        }
        
        // Verify ISVPRODID matches
        if (qeIsvprodid != expectedIdentity.isvprodid) {
            return false;
        }
        
        // Verify ISVSVN meets minimum
        if (qeIsvsvn < expectedIdentity.minIsvsvn) {
            return false;
        }
        
        // Verify attributes with mask
        bytes16 maskedAttrs = qeAttributes & expectedIdentity.attributesMask;
        bytes16 expectedAttrs = expectedIdentity.attributes & expectedIdentity.attributesMask;
        if (maskedAttrs != expectedAttrs) {
            return false;
        }
        
        // Verify miscselect with mask
        bytes4 maskedMisc = qeMiscselect & expectedIdentity.miscselectMask;
        bytes4 expectedMisc = expectedIdentity.miscselect & expectedIdentity.miscselectMask;
        if (maskedMisc != expectedMisc) {
            return false;
        }
        
        return true;
    }
}
```

---

## Collateral and PCCS

Collateral is the supporting data needed to verify a quote. Intel provides this through the Provisioning Certification Service ([PCS](https://api.portal.trustedservices.intel.com/)), typically cached locally via [PCCS](https://download.01.org/intel-sgx/sgx-dcap/).

### Collateral Components

| Component | Source | Purpose |
|-----------|--------|---------|
| PCK Certificate | PCS | Anchors trust in the platform attestation collateral |
| PCK CRL | PCS | Certificate revocation |
| Intermediate CA Cert | PCS | Chain link |
| Root CA Cert | Embedded | Trust anchor |
| TCBInfo | PCS | TCB level evaluation |
| QEIdentity | PCS | QE verification |

### Collateral Architecture

```mermaid
flowchart TD
    PCS["Intel PCS<br>(api.trustedservices.intel.com)"]
    
    LocalPCCS["Local PCCS<br>(Caching Layer)"]
    
    PCS -->|"Fetch HTTPS"| LocalPCCS
    
    LocalPCCS --> OffChain["Off-Chain Verifier<br>(Traditional)"]
    LocalPCCS --> OnChain["On-Chain PCCS<br>(Automata approach)"]
    
    OnChain --> DCAPVerifier["DCAP Verifier Contract<br>Reads collateral on-chain<br>Verifies quote"]
    
    style PCS fill:#3498db,color:#fff
    style OnChain fill:#9b59b6,color:#fff
    style DCAPVerifier fill:#27ae60,color:#fff
```

---

## DCAP Verification Pipeline

Putting it all together, here's the complete DCAP verification flow:

```mermaid
flowchart TD
    Input["Input<br>Quote + Collateral"]
    
    Step1["1. Parse Quote<br>• Extract header, report body<br>• Extract QE report<br>• Extract signature data<br><br>TDX: parse 584-byte TD report"]
    
    Step2["2. Verify PCK Chain<br>• Parse PCK certificate<br>• Verify chain to Intel Root<br>• Check validity periods<br>• Check CRL status"]
    
    Step3["3. Verify QE Identity<br>• Fetch QEIdentity<br>• Verify Intel signature<br>• Check MRSIGNER / ISVSVN<br>• Verify attributes with mask"]
    
    Step4["4. Evaluate TCB<br>• Extract FMSPC from PCK<br>• Fetch TCBInfo<br>• Match platform SVNs<br>• Determine status<br><br>TDX: also verify TDX Module"]
    
    Step5["5. Verify Quote Signature<br>• Reconstruct signed data<br>• Extract attestation key<br>• Verify ECDSA-P256"]
    
    Step6["6. Apply Policy<br>• MRENCLAVE match?<br>• Debug disabled?<br>• TCB acceptable?<br>• Report data valid?"]
    
    Output["Output<br>Verified / Rejected"]
    
    Input --> Step1
    Step1 --> Step2
    Step2 --> Step3
    Step3 --> Step4
    Step4 --> Step5
    Step5 --> Step6
    Step6 --> Output
    
    style Input fill:#3498db,color:#fff
    style Output fill:#27ae60,color:#fff
```

### Error Cases

| Step | Error | Cause |
|------|-------|-------|
| Parse | Invalid quote format | Corrupted or wrong version |
| QE Identity | MRSIGNER mismatch | Not Intel's QE |
| Cert Chain | Signature invalid | Tampering or wrong issuer |
| TCB | No matching level | Platform TCB too old |
| Quote Sig | Verification failed | Quote tampering |
| Policy | MRENCLAVE mismatch | Wrong enclave code |

Once the collateral model is clear, the on-chain question becomes an engineering tradeoff: which portions of the DCAP pipeline execute on-chain,
which remain off-chain, and how the resulting trust assumptions are exposed to applications.
---

## On-Chain Implementation

### Gas Breakdown

The following gas figures are rough order-of-magnitude estimates and vary
by implementation details, calldata size, and chain-specific precompile support.

| Operation | Gas (with RIP-7212) | Gas (without) |
|-----------|---------------------|---------------|
| Quote parsing | ~15,000 | ~15,000 |
| QE identity check | ~5,000 | ~5,000 |
| PCK chain (3 P-256 sigs) | ~10,000 | ~1,000,000+ |
| TCB evaluation | ~10,000 | ~10,000 |
| Quote signature | ~3,500 | ~350,000 |
| Policy checks | ~2,000 | ~2,000 |
| **Total** | **~46,000** | **~1,380,000** |

### Architecture Patterns

```mermaid
flowchart LR
    subgraph Pattern1["Full On-Chain (L2)"]
        Q1["Quote"] --> V1["DCAP Verifier"]
        PCCS1["On-Chain PCCS"] --> V1
        V1 --> R1["Result"]
    end
    
    subgraph Pattern2["ZK Proof"]
        Q2["Quote + Collateral"] --> ZK["Off-Chain ZK Prover"]
        ZK --> Proof["ZK Proof"]
        Proof --> V2["Groth16 Verifier"]
        V2 --> R2["Result"]
    end
    
    subgraph Pattern3["Optimistic"]
        Q3["Quote"] --> Submit["Submit Claim"]
        Submit --> Challenge{"Challenge?"}
        Challenge -->|Yes| FraudProof["Verify Fraud Proof"]
        Challenge -->|No| R3["Accept after delay"]
    end
```

| Pattern | Gas | Trust | Latency |
|---------|-----|-------|---------|
| Full On-Chain | ~86k (L2) | Trustless | Immediate |
| ZK Proof | ~200k | Trustless | 30-60s proving |
| Optimistic | ~25k | 1-of-N honest | Challenge period |

---

## Looking Ahead

DCAP provides the foundation for decentralized TEE verification. The certificate hierarchy, extension parsing, and TCB evaluation are now tractable on L2s with RIP-7212 support.

The next post covers cross-platform attestation—AMD SEV-SNP, AWS Nitro, and ARM CCA. Each has different certificate structures, cryptographic choices, and trust models. Building infrastructure that works across platforms requires understanding these differences.

---


**Previous:** [Part II — TEE Attestation Model](02-tee-attestation-model.md)  
**Next:** [Part IV — Cross-Platform Attestation](04-cross-platform-attestation.md)
