# Security policy

IRONVEIL is defensive supply-chain assurance research. Test only against local synthetic fixtures or
systems you own and are explicitly authorized to assess.

## Supported releases

| Version | Status |
|---|---|
| 0.1.x | Research preview; security fixes accepted |

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting feature when available. Do not open a public issue that
contains credentials, real critical-infrastructure details, private keys, live exploit instructions,
or information that creates immediate operational risk. Include the affected invariant, the smallest
safe synthetic reproduction, impact, and a proposed remediation if known.

## Safe testing boundary

Do not use IRONVEIL to attack external registries or build systems, impersonate vendors, target real
firmware, steal credentials, establish persistence, create implants, or interact with infrastructure
without authorization. Test keys and fictional firmware are not production material.

## Claims

Supply-chain evidence does not prove that software is benign or vulnerability-free. Local signatures
are not production PKI. Simulated target verification is not hardware secure boot. No government,
NIST, SLSA, Sigstore, TUF, Uptane, CISA, or standards-body endorsement is implied.

