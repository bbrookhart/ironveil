# Ten-minute reviewer guide

## 0–2 minutes: establish the thesis

Read the README opening, capability status, and limitations. Confirm that signature validity is
separate from source, builder, release, target, and installed-state authorization.

```bash
make bootstrap
ironveil status
```

## 2–4 minutes: inspect the golden chain

```bash
ironveil release verify RELEASE-00001
ironveil evidence verify RELEASE-00001
ironveil sbom verify golden
```

Expect `ALLOW`, a verified evidence manifest, and precision/recall of 1.0 against synthetic ground truth.

## 4–6 minutes: substitute the artifact

```bash
ironveil scenario run SCN-004
```

Expect a digest mismatch and `DENY`.

## 6–8 minutes: run BROKEN SEAL

```bash
ironveil experiment run BROKEN-SEAL
```

Inspect the denominator and confirm zero unauthorized full-chain installations. Treat the result as a
synthetic evaluation, not a universal security guarantee.

## 8–10 minutes: trace and recall

```bash
ironveil graph trace DEVICE-001
ironveil impact dependency pkg:generic/edgeproto@1.2.3
```

Confirm the trace connects reviewed revision → build → artifact → release → device and the impact query
reaches the synthetic mission function.

