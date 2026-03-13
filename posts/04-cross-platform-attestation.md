# Roots of Trust, Part IV: Cross-Platform Attestation

*X.509, TEE Attestation, and Verifiable Infrastructure*

---

The TEE landscape is fragmented. Intel SGX/TDX, AMD SEV-SNP, AWS Nitro, ARM CCA—each platform has its own attestation format, certificate hierarchy, and cryptographic choices. Building verification infrastructure that works across platforms requires understanding these differences.

This post examines the three major alternatives to Intel DCAP: AMD SEV-SNP, AWS Nitro Enclaves, and ARM CCA. For each, we cover the trust model, certificate structure, attestation format, and on-chain verification feasibility. The goal is a clear map of what works, what doesn't, and where the gaps are.

---

## The Fragmentation Problem

There is no universal TEE attestation standard. Each vendor designed their system independently:

| Platform | Vendor | Curve | Root of Trust | Quote Format |
|----------|--------|-------|---------------|--------------|
| SGX/TDX | Intel | P-256 | Silicon (fused key) | DCAP Quote v3/v4 |
| SEV-SNP | AMD | P-384 | Silicon (fused key) | Attestation Report |
| Nitro | AWS | P-384 | AWS HSM | COSE Sign1 (CBOR) |
| CCA | ARM | P-256/P-384 | Silicon (CCA token) | EAT (CBOR) |

This fragmentation creates challenges:

1. **No shared verification code:** Each platform needs custom parsing and validation logic
2. **Different cryptographic requirements:** P-384 has no EVM precompile
3. **Different trust assumptions:** Some root in silicon, others in cloud provider infrastructure
4. **Different collateral systems:** Intel has PCCS, AMD has KDS, AWS has their own infrastructure

For blockchain applications, this means either committing to a single platform or building abstraction layers.

---

## AMD SEV-SNP

AMD's Secure Encrypted Virtualization - Secure Nested Paging (SEV-SNP) provides VM-level isolation with memory encryption and integrity protection. It's AMD's answer to Intel TDX.

### Architecture Overview

```mermaid
flowchart TD
    subgraph Hypervisor["HYPERVISOR (Untrusted)"]
        VM1["Guest VM (SNP)\nEncrypted Memory"]
        VM2["Guest VM (SNP)\nEncrypted Memory"]
        VM3["Guest VM (Normal)\nPlaintext Memory"]
    end
    
    SP["AMD SECURE PROCESSOR (SP)\n• Manages encryption keys per VM\n• Handles attestation requests\n• Signs reports with VCEK\n• Enforces SNP memory integrity"]
    
    VM1 --> SP
    VM2 --> SP
    
    style SP fill:#e74c3c,color:#fff
    style VM1 fill:#27ae60,color:#fff
    style VM2 fill:#27ae60,color:#fff
```

### Certificate Chain

AMD uses a simpler three-certificate chain compared to Intel:

```mermaid
flowchart TD
    ARK["AMD ROOT KEY (ARK)\n• ECDSA P-384\n• Self-signed\n• One per CPU product line"]
    
    ASK["AMD SEV KEY (ASK)\n• ECDSA P-384\n• Intermediate CA\n• One per product line"]
    
    VCEK["VCEK\n(Versioned Chip Endorsement Key)\n• ECDSA P-384\n• Unique per CPU + TCB version\n• Retrieved from AMD KDS"]
    
    Report["ATTESTATION REPORT\n• Signed by VCEK\n• Contains measurement, policy"]
    
    ARK -->|signs| ASK
    ASK -->|signs| VCEK
    VCEK -->|signs| Report
    
    style ARK fill:#e74c3c,color:#fff
    style VCEK fill:#9b59b6,color:#fff
    style Report fill:#27ae60,color:#fff
```

### VCEK Certificate Extensions

The VCEK certificate contains AMD-specific extensions (OID 1.3.6.1.4.1.3704.1.3.1.*):

| Extension OID | Name | Content |
|---------------|------|---------|
| .1 | Boot Loader SVN | uint8 |
| .2 | TEE SVN | uint8 |
| .3 | SNP SVN | uint8 |
| .4 | Microcode SVN | uint8 |
| .5 | Hardware ID | 128 bytes |
| .6 | Chip ID | 64 bytes |

### SNP Attestation Report Structure

The SNP attestation report is a fixed 1184-byte structure:

```mermaid
flowchart TD
    subgraph Report["SNP ATTESTATION REPORT (1184 bytes)"]
        Header["Header (0x000-0x050)\n• Version (must be 2)\n• Guest SVN, Policy\n• Family ID, Image ID\n• VMPL, Sig Algorithm\n• Current TCB, Platform Info"]
        
        Measurement["Measurement (0x050-0x1B0)\n• Report Data (48 bytes)\n• Measurement (48 bytes, SHA-384)\n• Host Data, ID Key Digest\n• Author Key Digest\n• Report ID, Chip ID"]
        
        TCB["TCB Info (0x1B0-0x210)\n• Committed TCB\n• Current/Launch TCB\n• Reserved"]
        
        Signature["Signature (0x2B0-0x4B0)\n• ECDSA P-384 (512 bytes)\n• R || S format"]
    end
    
    Header --> Measurement --> TCB --> Signature
```

### The P-384 Challenge

AMD's use of P-384 (secp384r1) creates significant challenges for on-chain verification:

| Aspect | P-256 (Intel) | P-384 (AMD) |
|--------|---------------|-------------|
| EVM Precompile | RIP-7212 (3,450 gas) | None |
| Pure Solidity | ~350,000 gas | ~800,000–1,200,000 gas |
| Signature size | 64 bytes | 96 bytes |
| Public key size | 64 bytes | 96 bytes |

### On-Chain Strategy for AMD

Given the P-384 constraint, practical approaches:

```mermaid
flowchart LR
    subgraph ZK["Option 1: ZK Proof"]
        Report1[SNP Report] --> ZKCircuit[ZK Circuit]
        ZKCircuit --> Proof[Proof ~200k gas]
    end
    
    subgraph Oracle["Option 2: Threshold Oracle"]
        Report2[SNP Report] --> Oracles[Oracle Committee]
        Oracles --> Threshold[k-of-n Signatures]
        Threshold --> Accept[Accept ~25k gas]
    end
    
    style ZK fill:#9b59b6,color:#fff
    style Oracle fill:#f39c12,color:#fff
```

---

## AWS Nitro Enclaves

AWS Nitro Enclaves provide isolation on AWS infrastructure—but with a fundamentally different trust model. The root of trust is AWS's infrastructure, not silicon.

### Trust Model Difference

```mermaid
flowchart LR
    subgraph Silicon["Intel/AMD (Silicon Root)"]
        Q1[Quote] --> PCK1[PCK/VCEK]
        PCK1 --> Int1[Intermediate]
        Int1 --> Root1["Vendor Root\n(Silicon-fused)"]
        Root1 --> Trust1["Can't forge"]
    end
    
    subgraph AWS["AWS Nitro (HSM Root)"]
        Q2[Attestation] --> Cert2[Enclave Cert]
        Cert2 --> Int2[Intermediate]
        Int2 --> Root2["AWS Root CA\n(AWS HSM)"]
        Root2 --> Trust2["AWS could forge"]
    end
    
    style Root1 fill:#27ae60,color:#fff
    style Root2 fill:#f39c12,color:#fff
```

### Nitro Architecture

```mermaid
flowchart TD
    subgraph EC2["EC2 Instance"]
        Parent["Parent Instance\n• Runs main app\n• Has network/storage"]
        Enclave["Nitro Enclave\n• Isolated vCPUs\n• Isolated memory\n• No network/storage"]
        
        Parent <-->|vsock| Enclave
    end
    
    NSM["NITRO SECURITY MODULE (NSM)\n• Hardware on Nitro card\n• Generates attestation docs\n• Signs with AWS-rooted key\n• Provides RNG"]
    
    Enclave --> NSM
    
    style Enclave fill:#3498db,color:#fff
    style NSM fill:#9b59b6,color:#fff
```

### PCR-Based Measurements

Nitro uses Platform Configuration Registers (PCRs) instead of a single measurement hash:

| PCR | Content |
|-----|---------|
| PCR0 | Enclave image file hash |
| PCR1 | Linux kernel and bootstrap hash |
| PCR2 | Application hash |
| PCR3 | IAM role assigned to parent instance |
| PCR4 | Instance ID of parent instance |
| PCR8 | Enclave image file signing certificate |

### Attestation Document Format

Nitro attestations use COSE Sign1 (CBOR Object Signing and Encryption):

```mermaid
flowchart TD
    subgraph COSE["COSE_Sign1 Structure"]
        Protected["protected:\n• alg: ES384 (P-384)"]
        
        Payload["payload:\n• module_id\n• timestamp, digest\n• pcrs: {0: bytes48, 1: bytes48, ...}\n• certificate (DER X.509)\n• cabundle (CA chain)\n• public_key (optional)\n• user_data, nonce"]
        
        Signature["signature:\n• 96 bytes (P-384)"]
    end
    
    Protected --> Payload --> Signature
```

### Trust Implications

| Aspect | Intel/AMD | AWS Nitro |
|--------|-----------|-----------|
| Root key holder | Silicon (manufacturer can't extract) | AWS HSM |
| Forge attestation? | Impossible (without hardware compromise) | AWS could, theoretically |
| Audit root key? | No (but can't forge) | No (must trust AWS) |
| Collusion resistance | Manufacturer + attacker needed | AWS alone sufficient |

Nitro is appropriate when:
- You already trust AWS (e.g., AWS-hosted infrastructure)
- The threat model doesn't include AWS as adversary
- Convenience outweighs trust minimization

---

## ARM Confidential Compute Architecture (CCA)

ARM CCA is the newest entrant—designed for mobile and edge devices with increasing data center adoption.

### Architecture Overview

```mermaid
flowchart TD
    subgraph Normal["NORMAL WORLD"]
        HostOS["Host OS (Linux)"]
        HostApps["Host Applications"]
    end
    
    subgraph Realm["REALM WORLD"]
        R1["Realm 1 (VM)\nIsolated from host"]
        R2["Realm 2 (VM)\nIsolated from host"]
        R3["Realm 3 (VM)\nIsolated from host"]
    end
    
    RMM["REALM MANAGEMENT MONITOR (RMM)\n• Manages Realm lifecycle\n• Handles memory encryption\n• Generates attestation tokens\n• Runs at EL2 (isolated)"]
    
    RootOfTrust["ARM ROOT OF TRUST\n• Hardware-backed keys\n• Platform attestation"]
    
    Realm --> RMM
    RMM --> RootOfTrust
    
    style RMM fill:#9b59b6,color:#fff
    style RootOfTrust fill:#e74c3c,color:#fff
```

### CCA Attestation Token

CCA uses Entity Attestation Tokens (EAT) in CBOR format:

```mermaid
flowchart TD
    subgraph CCAToken["CCA_TOKEN"]
        Platform["CCA_PLATFORM_TOKEN (COSE_Sign1)\n• profile, challenge\n• implementation_id\n• instance_id, config\n• lifecycle state\n• sw_components[]\n• platform_hash_algo"]
        
        Realm["CCA_REALM_TOKEN (COSE_Sign1)\n• challenge\n• realm_initial_measurement (RIM)\n• realm_extensible_measurements (REMs)\n• realm_personalization_value\n• realm_public_key"]
    end
    
    Platform --> Realm
```

### On-Chain Status

ARM CCA is still emerging for blockchain use cases:

- **Limited tooling:** No equivalent to Automata's DCAP library
- **Variable cryptography:** P-256 or P-384 depending on implementation
- **CBOR parsing required:** Same challenge as Nitro
- **No production on-chain verifiers:** As of this writing

---

## Comparison Matrix

### Feature Comparison

| Feature | Intel SGX | Intel TDX | AMD SEV-SNP | AWS Nitro | ARM CCA |
|---------|-----------|-----------|-------------|-----------|---------|
| Isolation level | Process | VM | VM | VM | VM |
| Memory encryption | Yes | Yes | Yes | Yes | Yes |
| Root of trust | Silicon | Silicon | Silicon | AWS HSM | Silicon |
| Signature curve | P-256 | P-256 | P-384 | P-384 | P-256/P-384 |
| EVM precompile | RIP-7212 | RIP-7212 | None | None | Depends |
| On-chain maturity | High | Medium | Low | Low | None |

### On-Chain Verification Feasibility

```mermaid
flowchart TD
    subgraph Intel["Intel SGX/TDX"]
        I1["Native Solidity\n~86k gas (L2)"] --> OK1[✅ Production]
        I2["ZK Proof\n~200k gas"] --> OK2[✅ Production]
    end
    
    subgraph AMD["AMD SEV-SNP"]
        A1["Native Solidity\n~1.2M gas"] --> Warn1[⚠️ Expensive]
        A2["ZK Proof\n~200k gas"] --> OK3[✅ Practical]
    end
    
    subgraph AWS["AWS Nitro"]
        N1["Native Solidity\n~1.2M gas"] --> Warn2[⚠️ Expensive]
        N2["ZK Proof\n~200k gas"] --> OK4[✅ Practical]
    end
    
    subgraph ARM["ARM CCA"]
        C1["Native Solidity\nDepends"] --> Unknown[❓ No tooling]
        C2["ZK Proof\n~200k gas"] --> OK5[✅ Practical]
    end
```

### Trust Spectrum

```mermaid
flowchart LR
    Trustless["MORE TRUSTLESS"] -.-> Trust["MORE TRUST"]
    
    Intel["Intel SGX/TDX\nSilicon root\n(can't forge)"]
    AMD["AMD SEV-SNP\nSilicon root\n(can't forge)"]
    ARM["ARM CCA\nSilicon root\n(can't forge)"]
    AWS["AWS Nitro\nAWS HSM root\n(could forge)"]
    
    Intel --> AMD --> ARM --> AWS
    
    style Intel fill:#27ae60,color:#fff
    style AMD fill:#27ae60,color:#fff
    style ARM fill:#27ae60,color:#fff
    style AWS fill:#f39c12,color:#fff
```

---

## Unified Verification Strategy

Building cross-platform attestation infrastructure requires abstraction:

### Abstract Interface

```solidity
/// @title Universal Attestation Verifier
/// @notice Platform-agnostic attestation verification interface

interface IUniversalAttestationVerifier {
    enum Platform {
        INTEL_SGX,
        INTEL_TDX,
        AMD_SEV_SNP,
        AWS_NITRO,
        ARM_CCA
    }
    
    struct AttestationResult {
        Platform platform;
        bytes32 measurementHash;    // Normalized measurement
        bytes32 reportDataHash;     // User-provided binding
        uint64 timestamp;
        bool tcbCurrent;            // Is TCB up to date?
    }
    
    /// @notice Verify attestation from any supported platform
    function verify(
        Platform platform,
        bytes calldata attestation,
        bytes calldata proof
    ) external view returns (AttestationResult memory result);
    
    /// @notice Check if measurement is in approved set
    function isApprovedMeasurement(
        Platform platform,
        bytes32 measurementHash
    ) external view returns (bool);
}
```

### ZK Abstraction Pattern

Since ZK is the practical path for non-Intel platforms, design around it:

```mermaid
flowchart TD
    subgraph Platforms["Platform-Specific"]
        Intel[Intel Quote] --> IntelCircuit[Intel ZK Circuit]
        AMD[AMD Report] --> AMDCircuit[AMD ZK Circuit]
        AWS[Nitro Doc] --> AWSCircuit[AWS ZK Circuit]
    end
    
    subgraph Unified["Unified Interface"]
        IntelCircuit --> Proof[Normalized Proof]
        AMDCircuit --> Proof
        AWSCircuit --> Proof
        
        Proof --> Verifier[Multi-Platform Verifier]
        Verifier --> Result["AttestationResult\n• platform\n• measurementHash\n• reportDataHash"]
    end
    
    style Verifier fill:#9b59b6,color:#fff
    style Result fill:#27ae60,color:#fff
```

---

## Looking Ahead

Cross-platform attestation is becoming critical as the TEE landscape matures:

**Near-term:**
- ZK is the universal solution for non-Intel platforms
- Intel has first-mover advantage with RIP-7212
- AMD and AWS require ZK or oracle approaches

**Medium-term:**
- P-384 precompile proposals may emerge
- ARM CCA tooling will mature
- Unified attestation standards may develop

**Long-term:**
- Platform-agnostic verification becomes table stakes
- ZK circuits commoditize across platforms
- Trust model differences remain fundamental

The practical advice: design for abstraction. Use ZK verification where possible, build platform-agnostic interfaces, and prepare for a multi-vendor future.

---

---

**Previous:** [Part III — Intel DCAP Certificate Hierarchy](03-intel-dcap-certificate-hierarchy.md)  
**Next:** [Part V — Real-World Case Studies](05-real-world-case-studies.md)
