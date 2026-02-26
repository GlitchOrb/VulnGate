# Supply Chain Integrity Roadmap (Toward SLSA Level 4)

## Implemented Baseline (MVP)

- Reproducible CLI build path with pinned Go toolchain in CI.
- Cross-platform binary artifacts from CI.
- Clear module boundaries to support provenance attestation per component.

## Next Steps

1. Add artifact signing for release binaries (Sigstore/cosign workflow).
2. Emit in-toto attestations for build provenance.
3. Enforce dependency lock and verified checksums in CI.
4. Split privileged build steps from unprivileged test steps.
5. Introduce hermetic builds and deterministic containerized build roots.
6. Add hardware-backed provenance (HSM/KMS-backed keys, isolated runners).
7. Progress toward full SLSA Level 4 with two-person reviewed, tamper-resistant release path.

## Notes

- SLSA Level 4 is achieved incrementally; MVP focuses on foundations and compatibility.
- Air-gapped deployments can mirror signing and verification roots internally.
