# Legal / Ethical Use

Chronos is a **defensive security and research tool**.

## Observation-only

Chronos records behavior; it never acts against the sample:

- the tracer never patches memory, registers or control flow of the traced
  process;
- the sinkhole binds the loopback interface only, answers DNS with a
  loopback address, and serves **empty** HTTP responses — no payload is
  served, no traffic is relayed, nothing is redirected to third parties.

## Authorized use only

- Analyze **only** binaries you own, or that you are explicitly and lawfully
  authorized to analyze (authorized pentest engagements, security research
  agreements, incident response on systems you operate, CTF/lab
  environments).
- Do not use Chronos to instrument software you have no right to observe.
- Respect the legal framework of your jurisdiction. This tool provides
  behavioral *observation*; it does not exploit, and must not be used as a
  component in an attack chain.

## Obligations of the user

You are solely responsible for:

- obtaining all necessary authorizations before running any analysis,
- the samples you analyze,
- the use and dissemination of analysis results,
- ensuring you comply with applicable laws and policies.

The authors assume no liability for any misuse.

*If you are unsure whether you are authorized to analyze a given binary,
assume you are not.*
