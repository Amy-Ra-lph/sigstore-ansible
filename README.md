# sigstore-ansible

Ansible roles for deploying a private [Sigstore](https://sigstore.dev) infrastructure with IPA-native CA backends. Enables keyless code signing and transparency logging within a FreeIPA domain.

## What it does

Deploys a complete private Sigstore stack:

- **Fulcio** — keyless signing CA (issues short-lived certificates for authenticated identities)
- **Rekor** — transparency log (append-only Merkle tree for signing events)
- **cosign** — client tooling for signing and verifying artifacts
- **OIDC integration** — connects Fulcio to your identity provider (ahdapa or Keycloak)

## Roles

| Role | Purpose |
|------|---------|
| `sigstore_ca` | CA key and certificate provisioning (3 modes — see below) |
| `sigstore_fulcio` | Fulcio container deployment (Podman Quadlet) |
| `sigstore_rekor` | Rekor + Trillian + MariaDB container deployment |
| `sigstore_cosign` | cosign binary installation and trust bundle configuration |
| `sigstore_oidc` | OIDC client registration (ahdapa or Keycloak) |

## CA modes

The `sigstore_ca` role supports three CA backend modes:

| Mode | Key storage | Use case |
|------|-------------|----------|
| `ipathinca` | IPAthinCA sub-CA (key on disk) | PoC / development |
| `dogtag_csr` | Key generated locally, cert signed by Dogtag/RHCS | Sovereign / NIST-compliant |
| `dogtag_pkcs11` | Lightweight CA in Dogtag, key in NSS DB / HSM | Production |

Set the mode with `-e sigstore_ca_mode=<mode>` (default: `ipathinca`).

## Prerequisites

- FreeIPA server with DNS
- Podman (for Fulcio, Rekor, Trillian containers)
- `ansible-freeipa` collection (`ansible-galaxy collection install freeipa.ansible_freeipa`)
- One of: ahdapa (IPA-native IdP) or Keycloak (with IPA user federation)

## Quick start

```bash
# 1. Copy and edit environment + inventory
cp environments/example.yml environments/my-lab.yml
cp inventory/example.ini inventory/my-lab.ini
# Edit both files with your actual values

# 2. Deploy (IPAthinCA mode)
ansible-playbook playbooks/sigstore-deploy.yml \
  -i inventory/my-lab.ini \
  -e @environments/my-lab.yml

# 3. Deploy (Dogtag/RHCS mode)
ansible-playbook playbooks/sigstore-deploy.yml \
  -i inventory/my-lab.ini \
  -e sigstore_ca_mode=dogtag_csr \
  -e @environments/my-lab.yml

# 4. Validate
ansible-playbook playbooks/sigstore-test.yml \
  -i inventory/my-lab.ini \
  -e @environments/my-lab.yml
```

## Manual test

```bash
# On any sigstore client host
source /etc/profile.d/sigstore.sh

# Sign
echo "hello" > /tmp/artifact
cosign sign-blob /tmp/artifact \
  --fulcio-url=$SIGSTORE_FULCIO_URL \
  --rekor-url=$SIGSTORE_REKOR_URL \
  --oidc-issuer=$SIGSTORE_OIDC_ISSUER \
  --output-signature /tmp/artifact.sig \
  --output-certificate /tmp/artifact.crt

# Verify
cosign verify-blob /tmp/artifact \
  --signature /tmp/artifact.sig \
  --certificate /tmp/artifact.crt \
  --certificate-identity-regexp='.*' \
  --certificate-oidc-issuer-regexp='.*' \
  --rekor-url=$SIGSTORE_REKOR_URL
```

## License

Apache-2.0
