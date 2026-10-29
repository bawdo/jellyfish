# Security policy

jellyfish holds an Iru API token and, optionally, a Google Workspace
service-account key. Both live in the macOS Keychain, and the token is only
ever sent to the Iru origin derived from the configured subdomain and
region. Bugs that weaken either of those properties are security bugs.

## Supported versions

Only the newest release on the
[Releases page](https://github.com/bawdo/jellyfish/releases) receives
fixes. There are no maintenance branches.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private reporting form:
<https://github.com/bawdo/jellyfish/security/advisories/new>. It goes
straight to the maintainer and nobody else can see it.

Include what you can of: the command and flags involved, the version from
`jellyfish version`, what you expected, and what happened. A proof of
concept helps but is not required.

You will get an acknowledgement within seven days. A fix, or an explanation
of why the report is not being treated as a vulnerability, follows as a
published advisory and a release. Credit is given in the advisory unless
you ask otherwise.

## Verifying a release

Every release archive carries a build provenance attestation from the
release workflow, and a `checksums.txt` lists the archive digests. To
confirm a download came from this repository's CI and has not been
altered, run both against the archive you downloaded:

```bash
gh attestation verify jellyfish_<version>_darwin_<arch>.tar.gz --repo bawdo/jellyfish
shasum -a 256 -c checksums.txt --ignore-missing
```

The attestation is also attached to each release as a Sigstore bundle,
`jellyfish_<version>_provenance.sigstore.json`. Download it next to the
archive to verify without querying GitHub's attestation API:

```bash
gh attestation verify jellyfish_<version>_darwin_<arch>.tar.gz --repo bawdo/jellyfish \
  --bundle jellyfish_<version>_provenance.sigstore.json
```

On a machine with no network access at all, `gh` can't fetch the Sigstore
trusted root itself. Save it on a connected machine, copy it across and
pass it in:

```bash
gh attestation trusted-root > trusted_root.jsonl
gh attestation verify jellyfish_<version>_darwin_<arch>.tar.gz --repo bawdo/jellyfish \
  --bundle jellyfish_<version>_provenance.sigstore.json \
  --custom-trusted-root trusted_root.jsonl
```
