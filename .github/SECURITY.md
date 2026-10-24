# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's **Report a vulnerability** button
on this repository's Security tab (private vulnerability reporting). Do not open a public issue,
pull request, or discussion for a security problem, and do not include real hostnames, tokens,
or patient data in a report.

Reports are triaged by the repository's security team (the code owners in `.github/CODEOWNERS`). Expect an acknowledgement within
2 business days and a triage decision (severity, affected versions, plan) within 5 business days.

## Supported versions

Only the latest commit on `main`, and the broker build produced from it by CI, receives fixes.

## How dependencies and builds are controlled

- Runtime dependencies are locked in `uv.lock`. The broker installs from
  `requirements/broker-win.txt`, which is generated from that lock, lists a SHA-256 for every
  wheel, and forbids source builds (`pip install --require-hashes --no-deps`).
- CI runs lint (including security lint), tests with a coverage floor, `pip-audit` against
  every locked set, a full-history secret scan, and CodeQL on every pull request, plus a weekly
  scheduled re-audit.
- Each CI build publishes the wheel, `SHA256SUMS`, and a CycloneDX SBOM as artifacts; builds
  from `main` also carry a GitHub build-provenance attestation. Verify one with
  `gh attestation verify <wheel> --repo <owner>/<repo>` before deploying it.
- GitHub Actions are pinned to full commit SHAs and updated by Dependabot, which also proposes
  dependency updates after a 7-day cooldown.
