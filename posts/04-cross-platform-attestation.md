# Roots of Trust, Part IV: Cross-Platform Attestation

*X.509, TEE Attestation, and Verifiable Infrastructure*

---

The TEE landscape is fragmented. 
[Intel SGX](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html) /
[Intel TDX](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html),
[AMD SEV-SNP](https://www.amd.com/en/developer/sev.html),
[AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html),
and
[ARM Confidential Compute Architecture (CCA)](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture)
each have their own attestation format, certificate hierarchy, and cryptographic choices. Building verification infrastructure that works across platforms requires understanding these differences.

These certificate and report structures are straightforward to verify in native software, but they become much harder to handle inside the EVM. The main reason is AMD's choice of P-384 signatures.

This post examines the three major alternatives to [Intel Data Center Attestation Primitives (DCAP)](https://download.01.org/intel-sgx/sgx-dcap/): AMD SEV-SNP, AWS Nitro Enclaves, and ARM CCA. For each, we cover the trust model, certificate structure, attestation format, and on-chain verification feasibility. The goal is a clear map of what works, what doesn't, and where the gaps are.

---

## The Fragmentation Problem

There is no universal TEE attestation standard. Each vendor designed their system independently:

| Platform | Vendor | Curve | Root of Trust | Quote Format |
|----------|--------|-------|---------------|--------------|
| SGX/TDX | Intel | P-256 | Silicon (hardware-rooted keys) | DCAP Quote v3/v4 |
| SEV-SNP | AMD | P-384 | Silicon (hardware-rooted keys) | Attestation Report |
| Nitro | AWS | P-384 | AWS HSM | COSE Sign1 (CBOR) |
| CCA | ARM | P-256/P-384 | Silicon (CCA token) | EAT (CBOR) |

This fragmentation creates challenges:

1. **No shared verification code:** Each platform needs custom parsing and validation logic
2. **Different cryptographic requirements:** P-384 ([secp384r1](https://www.secg.org/sec2-v2.pdf)) has no EVM precompile
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
        VM1["Guest VM (SNP)<br>Encrypted Memory"]
        VM2["Guest VM (SNP)<br>Encrypted Memory"]
        VM3["Guest VM (Normal)<br>Plaintext Memory"]
    end
    
    SP["AMD SECURE PROCESSOR (SP)<br>• Manages encryption keys per VM<br>• Handles attestation requests<br>• Signs reports with VCEK<br>• Enforces SNP memory integrity"]
    
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
    ARK["AMD Root Key (ARK)<br>• ECDSA P-384<br>• Self-signed root CA<br>• One per CPU product line"]
    
    ASK["AMD SEV Key (ASK)<br>• ECDSA P-384<br>• Intermediate CA<br>• One per CPU product line"]
    
    VCEK["Versioned Chip Endorsement Key (VCEK)<br>• ECDSA P-384<br>• Unique per CPU + TCB version<br>• Retrieved from [AMD Key Distribution Service (KDS)](https://kdsintf.amd.com/)"]
    
    Report["Attestation Report<br>• Signed by VCEK<br>• Contains measurement and policy"]
    
    ARK -->|signs| ASK
    ASK -->|signs| VCEK
    VCEK -->|signs| Report
    
    style ARK fill:#e74c3c,color:#fff
    style ASK fill:#e67e22,color:#fff
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
        Header["Header (0x000–0x050)<br>• Version (must be 2)<br>• Guest SVN, policy<br>• Family ID, image ID<br>• VMPL, sig algorithm<br>• Current TCB, platform info"]
        
        Measurement["Measurement (0x050–0x1B0)<br>• Report data (48 bytes)<br>• Measurement (48 bytes, SHA-384)<br>• Host data, ID key digest<br>• Author key digest<br>• Report ID, chip ID"]
        
        TCB["TCB info (0x1B0–0x210)<br>• Committed TCB<br>• Current/launch TCB<br>• Reserved"]
        
        Signature["Signature (0x2B0–0x4B0)<br>• ECDSA P-384 (512 bytes)<br>• R || S format"]
    end
    
    Header --> Measurement --> TCB --> Signature

```
These certificate and report structures are straightforward to verify in
native software, but they become much harder to handle inside the EVM.
The main reason is AMD's choice of P-384 signatures.
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
        Report1["SNP Attestation Report"]
        ZKCircuit["ZK Circuit Verification"]
        Proof["On-chain proof verification<br>~200k gas"]

        Report1 --> ZKCircuit --> Proof
    end
    
    subgraph Oracle["Option 2: Threshold Oracle"]
        Report2["SNP Attestation Report"]
        Oracles["Oracle committee"]
        Threshold["k-of-n signatures"]
        Accept["On-chain signature check<br>~25k gas"]

        Report2 --> Oracles --> Threshold --> Accept
    end
    
    style ZK fill:#9b59b6,color:#fff,stroke:#333,stroke-width:1px
    style Oracle fill:#f39c12,color:#fff,stroke:#333,stroke-width:1px
```

---

## AWS Nitro Enclaves

[AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
provide isolated execution environments on AWS infrastructure—but with a fundamentally different trust model. Instead of vendor silicon keys, attestation chains to an AWS-managed root certificate anchored in the AWS Nitro infrastructure rather than CPU vendor silicon.

```mermaid
flowchart LR
    Intel["Intel SGX/TDX<br>Silicon root<br>(cannot forge)"]
    AMD["AMD SEV-SNP<br>Silicon root<br>(cannot forge)"]
    ARM["ARM CCA<br>Silicon root<br>(cannot forge)"]
    AWS["AWS Nitro<br>AWS HSM root<br>(AWS could forge)"]

    Intel --> AMD --> ARM --> AWS

    style Intel fill:#27ae60,color:#fff
    style AMD fill:#27ae60,color:#fff
    style ARM fill:#27ae60,color:#fff
    style AWS fill:#f39c12,color:#fff
```

### Nitro Architecture

```mermaid
flowchart TD
    subgraph EC2["EC2 Instance"]
        Parent["Parent instance<br>• Runs main app<br>• Has network/storage"]
        Enclave["Nitro Enclave<br>• Isolated vCPUs<br>• Isolated memory<br>• No network/storage"]
        
        Parent <-->|vsock| Enclave
    end
    
    NSM["Nitro Security Module (NSM)<br>• Hardware on Nitro card<br>• Generates attestation docs<br>• Signs with AWS-rooted key<br>• Provides RNG"]
    
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

Nitro attestation documents are encoded as
[COSE Sign1](https://datatracker.ietf.org/doc/html/rfc9052) objects
(CBOR Object Signing and Encryption). The signature covers the protected
headers and payload, while the payload itself is a
[CBOR](https://datatracker.ietf.org/doc/html/rfc8949)
structure containing PCR measurements, metadata, and certificate material.
```mermaid
flowchart TD
    subgraph COSE["COSE_Sign1 Structure"]
        Protected["protected<br>• alg: ES384 (P-384)"]
        
        Payload["payload<br>• module_id<br>• timestamp, digest<br>• pcrs: {0: bytes48, 1: bytes48, ...}<br>• certificate (DER X.509)<br>• cabundle (CA chain)<br>• public_key (optional)<br>• user_data, nonce"]
        
        Signature["signature<br>• 96 bytes (ECDSA P-384)"]
    end
    
    Protected -.included in signing.- Signature
    Payload -.included in signing.- Signature
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

[ARM Confidential Compute Architecture (CCA)](https://developer.arm.com/documentation/den0125/latest)
is the newest entrant in the TEE landscape—initially designed for mobile
and edge systems but increasingly targeted at data center deployments.

CCA introduces a new execution environment called a **Realm**.
Realms are isolated virtual machines whose memory and execution state
are protected from the host operating system and hypervisor.

Realm lifecycle and isolation are enforced by the
[Realm Management Monitor (RMM)](https://developer.arm.com/documentation/den0137/latest),
a privileged component that runs at EL2 and mediates all transitions
between the normal world and the Realm world.

### Architecture Overview

```mermaid

flowchart TD
    subgraph Normal["NORMAL WORLD"]
        HostOS["Host OS (Linux)"]
        HostApps["Host Applications"]
    end
    
    subgraph Realm["REALM WORLD"]
        R1["Realm 1 (VM)<br>Isolated from host"]
        R2["Realm 2 (VM)<br>Isolated from host"]
        R3["Realm 3 (VM)<br>Isolated from host"]
    end
    
    RMM["Realm Management Monitor (RMM)<br>• Manages Realm lifecycle<br>• Mediates host/realm transitions<br>• Handles memory protection<br>• Runs at EL2"]
    
    RootOfTrust["Platform Root of Trust<br>• Hardware-backed keys<br>• Platform attestation"]
    
    RMM --> R1
    RMM --> R2
    RMM --> R3
    
    RMM --> RootOfTrust
    
    style RMM fill:#9b59b6,color:#fff
    style RootOfTrust fill:#e74c3c,color:#fff
```

### CCA Attestation Token

CCA uses Entity Attestation Tokens (EAT) in [CBOR](https://datatracker.ietf.org/doc/html/rfc8949) format:

```mermaid
flowchart TD
    subgraph CCAToken["CCA_TOKEN"]
        Platform["CCA_PLATFORM_TOKEN (COSE_Sign1)<br>• profile, challenge<br>• implementation_id<br>• instance_id, config<br>• lifecycle state<br>• sw_components[]<br>• platform_hash_algo"]
        
        Realm["CCA_REALM_TOKEN (COSE_Sign1)<br>• challenge<br>• realm_initial_measurement (RIM)<br>• realm_extensible_measurements (REMs)<br>• realm_personalization_value<br>• realm_public_key"]
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
flowchart TB

    H1["Platform"]
    H2["Approach"]
    H3["Assessment"]

    H1 --- H2
    H2 --- H3

    P1["Intel SGX/TDX"] --- A1["Native Solidity<br>~86k gas (L2)"] --- R1["✅ Production"]
    P2["Intel SGX/TDX"] --- A2["ZK Proof<br>~200k gas"] --- R2["✅ Production"]

    P3["AMD SEV-SNP"] --- A3["Native Solidity<br>~1.2M gas"] --- R3["⚠️ Expensive"]
    P4["AMD SEV-SNP"] --- A4["ZK Proof<br>~200k gas"] --- R4["✅ Practical"]

    P5["AWS Nitro"] --- A5["Native Solidity<br>~1.2M gas"] --- R5["⚠️ Expensive"]
    P6["AWS Nitro"] --- A6["ZK Proof<br>~200k gas"] --- R6["✅ Practical"]

    P7["ARM CCA"] --- A7["Native Solidity<br>Depends"] --- R7["❓ No tooling"]
    P8["ARM CCA"] --- A8["ZK Proof<br>~200k gas"] --- R8["✅ Practical"]
```

### Trust Spectrum

```mermaid
flowchart LR
    Trustless["MORE TRUSTLESS"]
    Trust["MORE TRUST"]

    Intel["Intel SGX/TDX<br>Silicon root"]
    AMD["AMD SEV-SNP<br>Silicon root"]
    ARM["ARM CCA<br>Silicon root"]
    AWS["AWS Nitro<br>AWS HSM root"]

    Trustless --> Intel
    Intel --> AMD --> ARM --> AWS --> Trust

    style Intel fill:#27ae60,color:#fff
    style AMD fill:#27ae60,color:#fff
    style ARM fill:#27ae60,color:#fff
    style AWS fill:#f39c12,color:#fff
    
    style Trustless fill:#2ecc71,color:#fff
    style Trust fill:#e67e22,color:#fff
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
        Intel["Intel Quote"] --> IntelCircuit["Intel ZK Circuit"]
        AMD["AMD Report"] --> AMDCircuit["AMD ZK Circuit"]
        AWS["Nitro Doc"] --> AWSCircuit["AWS ZK Circuit"]
    end
    
    subgraph Unified["Unified Interface"]
        IntelCircuit --> Proof["Normalized Proof"]
        AMDCircuit --> Proof
        AWSCircuit --> Proof
        
        Proof --> Verifier["Multi-Platform Verifier"]
        Verifier --> Result["AttestationResult<br>• platform<br>• measurementHash<br>• reportDataHash"]
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

**Previous:** [Part III — Intel DCAP Certificate Hierarchy](03-intel-dcap-certificate-hierarchy.md)  
**Next:** [Part V — Real-World Case Studies](05-real-world-case-studies.md)
