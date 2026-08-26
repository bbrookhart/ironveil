# Limitations

1. Source control and review evidence is synthetic; live GitHub protections are not independently verified.
2. The local builder is not a hardened hosted build platform, so SLSA Build L2/L3 is not claimed.
3. Offline Ed25519 signing is test-only and lacks Sigstore workload identity and transparency evidence.
4. Update checks model TUF security semantics but do not establish TUF or Uptane conformance.
5. SBOM metrics apply only to explicit synthetic ground truth and do not establish scanner accuracy on arbitrary artifacts.
6. Vulnerability data is synthetic; no claim is made that VEILNODE or its dependencies are vulnerability-free.
7. Target state, measurement, clock, maintenance window, and health checks are simulated.
8. A compromised verifier, trust root, policy configuration, authoritative device inventory, filesystem, or clock is outside the evaluated protection claim.
9. Verification latency is a local-fixture measurement, not a production performance benchmark.
10. The graph contains one release and one device in v0.1; blast-radius behavior at fleet scale is future work.

