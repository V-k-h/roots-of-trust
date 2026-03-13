# References

External documentation, specifications, and resources referenced throughout the series.

---

## Intel Documentation

- [Intel SGX DCAP Documentation](https://download.01.org/intel-sgx/sgx-dcap/)
- [Intel TDX Specification](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- [Provisioning Certification Service API](https://api.portal.trustedservices.intel.com/)
- [Intel SGX Developer Reference](https://download.01.org/intel-sgx/sgx-linux/2.19/docs/)

---

## AMD Documentation

- [AMD SEV-SNP ABI Specification](https://www.amd.com/system/files/TechDocs/56860.pdf)
- [AMD Key Distribution Service (KDS)](https://kdsintf.amd.com/)
- [AMD SEV Firmware ABI](https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf)

---

## AWS Documentation

- [AWS Nitro Enclaves User Guide](https://docs.aws.amazon.com/enclaves/latest/user/)
- [Nitro Enclaves Attestation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
- [AWS Nitro System](https://aws.amazon.com/ec2/nitro/)

---

## ARM Documentation

- [ARM Confidential Compute Architecture](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture)
- [ARM CCA Realm Management Extension](https://developer.arm.com/documentation/den0137/latest)

---

## Ethereum Standards

- [RIP-7212: Precompile for secp256r1 Curve Support](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md)
- [EIP-7951: Precompile P256verify](https://eips.ethereum.org/EIPS/eip-7951)
- [EIP-198: Big integer modular exponentiation (modexp)](https://eips.ethereum.org/EIPS/eip-198)

---

## Production Implementations

| Project | Description | Repository |
|---------|-------------|------------|
| Automata Network | On-chain DCAP verification | [automata-dcap-attestation](https://github.com/automata-network/automata-dcap-attestation) |
| Taiko Raiko | Multi-prover framework | [raiko](https://github.com/taikoxyz/raiko) |
| Puffer Finance | RAVe attestation contracts | [rave](https://github.com/PufferFinance/rave) |
| Scroll | SGX prover | [sgx-prover](https://github.com/scroll-tech/sgx-prover) |
| Flashbots | SUAVE TEE coprocessor | [suave-geth](https://github.com/flashbots/suave-geth) |

---

## Research & Articles

- [Oasis Network: TEE Attestation Is Not Enough](https://oasisprotocol.org/blog/tee-attestation-is-not-enough)
- [Intel SGX Explained (Costan & Devadas)](https://eprint.iacr.org/2016/086.pdf)
- [Flashbots: Building Sirrah](https://writings.flashbots.net/suave-tee-coprocessor)
- [Taiko: Multi-Proofs](https://taiko.mirror.xyz/multi-proofs)

---

## Enclave Development Frameworks

- [Gramine](https://gramineproject.io/) — Run unmodified Linux apps in SGX
- [Occlum](https://github.com/occlum/occlum) — Memory-safe LibOS for SGX
- [EGo](https://github.com/edgelesssys/ego) — Go SDK for SGX enclaves
- [Enarx](https://enarx.dev/) — Platform-agnostic TEE runtime

---

## ZK Tooling for Attestation

- [RISC Zero](https://www.risczero.com/) — zkVM for general computation
- [SP1](https://github.com/succinctlabs/sp1) — zkVM from Succinct
- [zkemail](https://github.com/zkemail) — ZK circuits for email/ASN.1
- [Rarimo](https://rarimo.com/) — ZK passport verification
