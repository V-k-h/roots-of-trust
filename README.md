# Roots of Trust

**X.509, TEE Attestation, and Verifiable Infrastructure**

A technical blog series examining how Trusted Execution Environments (TEEs) enable verifiable infrastructure for blockchain systems.

The series focuses on attestation verification, certificate chains, and the practical constraints of implementing TEE verification in smart contracts.

Written for blockchain and infrastructure engineers who need to understand or implement TEE attestation verification.

**Keywords:** TEE, SGX, attestation, DCAP, confidential computing, SEV-SNP, zk proofs, blockchain infrastructure

---

## The Series

| # | Title | Topics |
|---|-------|--------|
| 1 | [X.509 Verification On-Chain](posts/01-x509-verification-on-chain.md) | ASN.1/DER parsing, P-256 vs secp256k1, RIP-7212, verification approaches |
| 2 | [TEE Attestation Model](posts/02-tee-attestation-model.md) | Local/remote attestation, measurements, quotes, trust anchors, ZK circuits |
| 3 | [Intel DCAP Certificate Hierarchy](posts/03-intel-dcap-certificate-hierarchy.md) | DCAP vs EPID, PCK extensions, FMSPC, TCBInfo, QE identity, Solidity patterns |
| 4 | [Cross-Platform Attestation](posts/04-cross-platform-attestation.md) | AMD SEV-SNP, AWS Nitro, ARM CCA, P-384 challenge, unified interfaces |
| 5 | [Real-World Case Studies](posts/05-real-world-case-studies.md) | Flashbots SUAVE, Taiko Raiko, Puffer Secure-Signer, Scroll TEE Prover |

---

## Quick Reference

### Gas Costs

| Approach | Gas | Notes |
|----------|-----|-------|
| P-256 verification (RIP-7212) | ~3,450 | L2 precompile |
| P-256 (Pure Solidity) | ~350,000 | Expensive |
| P-384 (Pure Solidity) | ~800,000+ | AMD SEV-SNP |
| Full DCAP verification (L2) | ~86,000 | With RIP-7212 |
| ZK Proof (Groth16) | ~200,000 | Any platform |
| ecrecover | ~3,000 | For reference |

### Trust Spectrum

```
Silicon Root (can't forge)              Cloud Root (could forge)
├── Intel SGX/TDX                       └── AWS Nitro
├── AMD SEV-SNP
└── ARM CCA
```

---

## Code Examples

Solidity snippets in the posts illustrate verification patterns and are not production-ready implementations.

| Project | Focus | Repository |
|---------|-------|------------|
| Automata Network | DCAP verification | [automata-dcap-attestation](https://github.com/automata-network/automata-dcap-attestation) |
| Taiko | Multi-prover (SGX + ZK) | [raiko](https://github.com/taikoxyz/raiko) |
| Puffer Finance | Validator anti-slashing | [rave](https://github.com/PufferFinance/rave) |
| Scroll | TEE block proving | [sgx-prover](https://github.com/scroll-tech/sgx-prover) |

---

## References

See [references.md](references.md) for documentation, specifications, and further reading.

---

## License

Content is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## Contributing

Found an error or have a suggestion? Open an issue or submit a pull request.

## Note

Some editing, formatting, and diagram generation in this series were assisted by AI tools. All technical content and verification decisions were written and reviewed by the author.
