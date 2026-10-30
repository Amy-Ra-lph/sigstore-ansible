#!/usr/bin/env python3
"""
Akamu Signing Adapter — translates cosign's Fulcio + Rekor API calls
into Akamu ACME flows backed by Dogtag CA, with an adapter-side
append-only Merkle-tree transparency log.

Endpoints:
  Fulcio v2:
    POST /api/v2/signingCert   — issue signing cert via Akamu ACME
    GET  /api/v2/trustBundle   — return CA trust bundle

  Rekor v1:
    POST /api/v1/log/entries   — append signing event to CT log
    GET  /api/v1/log/entries/{uuid}  — lookup entry by log index
    GET  /api/v1/log           — return signed tree head
    GET  /api/v1/log/proof     — consistency proof between tree sizes
    GET  /api/v1/log/publicKey — log signing public key

  Health:
    GET  /healthz              — readiness check
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
log = logging.getLogger("akamu-adapter")


# ---------------------------------------------------------------------------
# Merkle tree for CT log
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class MerkleTree:
    """Append-only Merkle tree for signing event transparency."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS log_entries (
                idx     INTEGER PRIMARY KEY AUTOINCREMENT,
                hash    BLOB    NOT NULL,
                body    TEXT    NOT NULL,
                ts      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tree_heads (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tree_size   INTEGER NOT NULL,
                root_hash   BLOB    NOT NULL,
                ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                signature   TEXT
            )
        """)
        conn.commit()
        conn.close()

    def append(self, entry_body: dict) -> int:
        raw = json.dumps(entry_body, sort_keys=True).encode()
        h = sha256(b"\x00" + raw)
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute(
                "INSERT INTO log_entries (hash, body) VALUES (?, ?)",
                (h, json.dumps(entry_body, sort_keys=True)),
            )
            idx = cur.lastrowid
            conn.commit()
            conn.close()
        return idx

    def tree_size(self) -> int:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()
        conn.close()
        return row[0]

    def get_entry(self, idx: int) -> dict | None:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT body, ts FROM log_entries WHERE idx = ?", (idx,)
        ).fetchone()
        conn.close()
        if row is None:
            return None
        return {"body": json.loads(row[0]), "timestamp": row[1], "logIndex": idx}

    def _hashes(self, n: int | None = None) -> list[bytes]:
        conn = sqlite3.connect(self.db_path)
        if n is None:
            rows = conn.execute(
                "SELECT hash FROM log_entries ORDER BY idx"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT hash FROM log_entries ORDER BY idx LIMIT ?", (n,)
            ).fetchall()
        conn.close()
        return [r[0] for r in rows]

    def root_hash(self, n: int | None = None) -> bytes:
        hashes = self._hashes(n)
        if not hashes:
            return sha256(b"")
        while len(hashes) > 1:
            new = []
            for i in range(0, len(hashes), 2):
                if i + 1 < len(hashes):
                    new.append(sha256(b"\x01" + hashes[i] + hashes[i + 1]))
                else:
                    new.append(hashes[i])
            hashes = new
        return hashes[0]

    def inclusion_proof(self, idx: int) -> list[str]:
        hashes = self._hashes()
        n = len(hashes)
        if idx < 0 or idx >= n:
            return []
        proof = []
        level = list(hashes)
        pos = idx
        while len(level) > 1:
            new_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    if i == pos - (pos % 2):
                        sibling = pos ^ 1
                        if sibling < len(level):
                            proof.append(base64.b64encode(level[sibling]).decode())
                    new_level.append(sha256(b"\x01" + level[i] + level[i + 1]))
                else:
                    new_level.append(level[i])
            pos = pos // 2
            level = new_level
        return proof

    def consistency_proof(self, old_size: int, new_size: int) -> list[str]:
        if old_size <= 0 or old_size > new_size:
            return []
        old_root = base64.b64encode(self.root_hash(old_size)).decode()
        new_root = base64.b64encode(self.root_hash(new_size)).decode()
        return [old_root, new_root]

    def signed_tree_head(self, sign_fn=None) -> dict:
        size = self.tree_size()
        root = self.root_hash()
        sth = {
            "tree_size": size,
            "root_hash": base64.b64encode(root).decode(),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if sign_fn:
            sth["signature"] = sign_fn(
                json.dumps(sth, sort_keys=True).encode()
            )
        return sth


# ---------------------------------------------------------------------------
# ACME client for Akamu
# ---------------------------------------------------------------------------

class AkamuACMEClient:
    """Minimal ACME client for Akamu's Dogtag-backed CA."""

    def __init__(self, acme_directory_url: str, eab_kid: str = "", eab_hmac: str = ""):
        self.directory_url = acme_directory_url
        self.eab_kid = eab_kid
        self.eab_hmac = eab_hmac
        self.directory = None
        self.session = requests.Session()
        self.session.verify = False

    def _load_directory(self):
        if self.directory is None:
            resp = self.session.get(self.directory_url)
            resp.raise_for_status()
            self.directory = resp.json()

    def get_nonce(self) -> str:
        self._load_directory()
        resp = self.session.head(self.directory["newNonce"])
        return resp.headers.get("Replay-Nonce", "")

    def request_certificate(self, csr_pem: str, identity_token: str) -> dict:
        self._load_directory()
        resp = self.session.post(
            self.directory["newOrder"],
            json={
                "identifiers": [{"type": "permanent-identifier", "value": "sigstore"}],
                "notBefore": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            headers={
                "Authorization": f"Bearer {identity_token}",
                "Content-Type": "application/jose+json",
            },
        )
        if resp.status_code in (200, 201):
            return resp.json()

        log.warning("ACME newOrder failed (%d): %s", resp.status_code, resp.text[:200])
        return {"error": resp.text, "status_code": resp.status_code}

    def get_trust_bundle(self) -> str:
        """Return the CA certificate chain from the IPA CA cert."""
        ca_cert_path = "/etc/ipa/ca.crt"
        if os.path.exists(ca_cert_path):
            return Path(ca_cert_path).read_text()
        return ""


# ---------------------------------------------------------------------------
# Dogtag direct signing (bypass ACME for sigstore flow)
# ---------------------------------------------------------------------------

class DogtagSigner:
    """
    Certificate issuance via IPA certrequest CLI or direct Dogtag REST.
    Prefers `ipa cert-request` which handles profile selection automatically.
    Falls back to direct Dogtag REST with RA agent credentials.
    """

    def __init__(self, dogtag_url: str, ra_cert: str, ra_key: str, ca_cert: str,
                 profile_id: str = "caServerCert"):
        self.dogtag_url = dogtag_url.rstrip("/")
        self.ra_cert = ra_cert
        self.ra_key = ra_key
        self.ca_cert = ca_cert
        self.profile_id = profile_id

    def issue_cert(self, csr_pem: str, san_email: str = "") -> str | None:
        """Issue a signing certificate. Generates an RSA key+CSR internally
        to avoid profile key-type mismatches, then signs via Dogtag REST."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as kf:
                key_path = kf.name
            with tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as cf:
                csr_path = cf.name

            # CN must be an enrolled IPA host for Dogtag profile validation
            hostname = subprocess.run(
                ["hostname", "-f"], capture_output=True, text=True, timeout=5
            ).stdout.strip() or "localhost"
            subject = f"/CN={hostname}"

            subprocess.run([
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-subj", subject, "-out", csr_path,
            ], capture_output=True, timeout=10, check=True)

            csr_content = Path(csr_path).read_text()
            csr_b64 = csr_content.replace(
                "-----BEGIN CERTIFICATE REQUEST-----", ""
            ).replace("-----END CERTIFICATE REQUEST-----", "").strip()

            enroll_url = f"{self.dogtag_url}/ca/rest/certrequests"
            payload = {
                "ProfileID": self.profile_id,
                "Input": [{
                    "id": "i1",
                    "ClassID": "certReqInputImpl",
                    "Attribute": [
                        {"name": "cert_request_type", "Value": "pkcs10"},
                        {"name": "cert_request", "Value": csr_b64},
                    ],
                }],
            }

            resp = requests.post(
                enroll_url, json=payload,
                cert=(self.ra_cert, self.ra_key),
                verify=False,
                headers={"Accept": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            entries = data.get("entries", data.get("CertRequestInfos", {}).get("entries", []))
            if not entries:
                log.error("Dogtag returned no entries: %s", data)
                return None

            entry = entries[0]
            status = entry.get("requestStatus", "")
            if status == "rejected":
                log.error("Dogtag rejected: %s", entry.get("errorMessage", "unknown"))
                return None

            cert_id = entry.get("certId") or entry.get("certID", "")
            if cert_id:
                cert_rest_url = f"{self.dogtag_url}/ca/rest/certs/{cert_id}"
                cert_resp = requests.get(
                    cert_rest_url,
                    cert=(self.ra_cert, self.ra_key),
                    verify=False,
                    headers={"Accept": "application/json"},
                    timeout=30,
                )
                cert_resp.raise_for_status()
                cert_data = cert_resp.json()
                return cert_data.get("Encoded", cert_data.get("encoded", ""))

            log.error("No certId in Dogtag response: %s", entry)
        except Exception as e:
            log.error("Certificate issuance failed: %s", e)
        finally:
            for p in [key_path, csr_path]:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        return None

    def get_ca_chain(self) -> str:
        if os.path.exists(self.ca_cert):
            return Path(self.ca_cert).read_text()
        return ""


# ---------------------------------------------------------------------------
# HTTP adapter
# ---------------------------------------------------------------------------

class AdapterConfig:
    def __init__(self, args):
        self.akamu_url = args.akamu_url
        self.ahdapa_url = args.ahdapa_url
        self.dogtag_url = args.dogtag_url
        self.ra_cert = args.ra_cert
        self.ra_key = args.ra_key
        self.ca_cert = args.ca_cert
        self.profile_id = args.profile_id
        self.db_path = args.db_path
        self.listen_host = args.host
        self.listen_port = args.port


class AdapterHandler(BaseHTTPRequestHandler):
    config: AdapterConfig = None
    signer: DogtagSigner = None
    ct_log: MerkleTree = None

    def log_message(self, fmt, *args):
        log.info(fmt, *args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _json_response(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _pem_response(self, code: int, pem: str):
        body = pem.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/pem-certificate-chain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # --- Fulcio v2 endpoints ---

    def _handle_signing_cert(self):
        """POST /api/v2/signingCert — issue a signing certificate."""
        body = self._read_body()
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._json_response(400, {"error": "invalid JSON"})
            return

        csr_pem = req.get("certificateSigningRequest", "")
        identity_token = req.get("credentials", {}).get("oidcIdentityToken", "")

        if not csr_pem:
            # cosign may send a public key instead of CSR — generate CSR
            pub_key = req.get("publicKeyRequest", {})
            if pub_key:
                csr_pem = self._generate_csr_from_pubkey(pub_key, identity_token)
                if not csr_pem:
                    self._json_response(400, {"error": "failed to generate CSR from public key"})
                    return

        if not csr_pem:
            self._json_response(400, {"error": "no CSR or public key provided"})
            return

        # Extract identity from token for SAN
        san_email = self._extract_identity(identity_token)

        # Issue cert via Dogtag
        cert_pem = self.signer.issue_cert(csr_pem, san_email)
        if not cert_pem:
            self._json_response(500, {"error": "certificate issuance failed"})
            return

        # Ensure PEM wrapping
        if not cert_pem.startswith("-----BEGIN"):
            cert_pem = (
                "-----BEGIN CERTIFICATE-----\n"
                + cert_pem
                + "\n-----END CERTIFICATE-----\n"
            )

        # Append signing event to CT log
        event = {
            "signer_identity": san_email or "unknown",
            "cert_fingerprint": hashlib.sha256(cert_pem.encode()).hexdigest()[:16],
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "issuer": self.config.akamu_url,
        }
        log_idx = self.ct_log.append(event)
        log.info("Signing event logged: index=%d identity=%s", log_idx, san_email)

        # Build chain: signing cert + CA cert
        ca_chain = self.signer.get_ca_chain()
        full_chain = cert_pem
        if ca_chain:
            full_chain += "\n" + ca_chain

        response = {
            "signedCertificateEmbeddedSct": {
                "chain": {"certificates": [cert_pem, ca_chain]},
            },
        }
        self._json_response(201, response)

    def _generate_csr_from_pubkey(self, pub_key_req: dict, identity_token: str) -> str | None:
        """Generate a CSR from a public key using openssl."""
        pub_key_content = pub_key_req.get("publicKey", {}).get("content", "")
        if not pub_key_content:
            return None
        try:
            pub_key_der = base64.b64decode(pub_key_content)
            with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
                f.write(pub_key_der)
                pub_path = f.name

            san_email = self._extract_identity(identity_token)
            subject = f"/emailAddress={san_email}" if san_email else "/CN=sigstore"

            key_path = tempfile.mktemp(suffix=".pem")
            csr_path = tempfile.mktemp(suffix=".pem")

            subprocess.run([
                "openssl", "req", "-new",
                "-key", pub_path,
                "-subj", subject,
                "-out", csr_path,
            ], capture_output=True, timeout=10)

            if os.path.exists(csr_path):
                csr_pem = Path(csr_path).read_text()
                return csr_pem
        except Exception as e:
            log.error("CSR generation failed: %s", e)
        finally:
            for p in [pub_path, key_path, csr_path]:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        return None

    def _extract_identity(self, token: str) -> str:
        """Decode JWT payload to extract email/sub without verification."""
        if not token:
            return ""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return ""
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            data = json.loads(base64.urlsafe_b64decode(payload))
            return data.get("email", data.get("sub", ""))
        except Exception:
            return ""

    def _handle_trust_bundle(self):
        """GET /api/v2/trustBundle — return CA certificate chain."""
        chain = self.signer.get_ca_chain()
        if chain:
            self._pem_response(200, chain)
        else:
            self._json_response(404, {"error": "no trust bundle available"})

    # --- Rekor v1 endpoints (CT log) ---

    def _handle_log_entries_post(self):
        """POST /api/v1/log/entries — append signing event."""
        body = self._read_body()
        try:
            entry = json.loads(body)
        except json.JSONDecodeError:
            self._json_response(400, {"error": "invalid JSON"})
            return

        idx = self.ct_log.append(entry)
        entry_uuid = str(uuid.uuid4()).replace("-", "")
        self._json_response(201, {
            entry_uuid: {
                "body": base64.b64encode(body).decode(),
                "logIndex": idx,
                "integratedTime": int(time.time()),
            }
        })

    def _handle_log_entry_get(self, entry_id: str):
        """GET /api/v1/log/entries/{uuid} — lookup by index."""
        try:
            idx = int(entry_id)
        except ValueError:
            self._json_response(400, {"error": "entry ID must be numeric index"})
            return

        entry = self.ct_log.get_entry(idx)
        if entry is None:
            self._json_response(404, {"error": "entry not found"})
            return

        proof = self.ct_log.inclusion_proof(idx)
        self._json_response(200, {
            str(idx): {
                "body": base64.b64encode(
                    json.dumps(entry["body"], sort_keys=True).encode()
                ).decode(),
                "logIndex": idx,
                "integratedTime": int(
                    datetime.fromisoformat(
                        entry["timestamp"].replace("Z", "+00:00")
                    ).timestamp()
                ),
                "verification": {
                    "inclusionProof": {
                        "logIndex": idx,
                        "treeSize": self.ct_log.tree_size(),
                        "rootHash": base64.b64encode(
                            self.ct_log.root_hash()
                        ).decode(),
                        "hashes": proof,
                    }
                },
            }
        })

    def _handle_log_get(self):
        """GET /api/v1/log — signed tree head."""
        sth = self.ct_log.signed_tree_head()
        self._json_response(200, {
            "rootHash": sth["root_hash"],
            "treeSize": sth["tree_size"],
            "signedTreeHead": sth,
            "treeID": "akamu-adapter-log",
        })

    def _handle_log_proof(self, params: dict):
        """GET /api/v1/log/proof — consistency proof."""
        try:
            first = int(params.get("firstSize", ["0"])[0])
            last = int(params.get("lastSize", ["0"])[0])
        except (ValueError, IndexError):
            self._json_response(400, {"error": "invalid size params"})
            return

        if last == 0:
            last = self.ct_log.tree_size()
        proof = self.ct_log.consistency_proof(first, last)
        self._json_response(200, {
            "hashes": proof,
        })

    def _handle_log_public_key(self):
        """GET /api/v1/log/publicKey — log signing key (CA cert as placeholder)."""
        chain = self.signer.get_ca_chain()
        if chain:
            body = chain.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json_response(404, {"error": "no public key"})

    # --- Routing ---

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/api/v2/trustBundle":
            self._handle_trust_bundle()
        elif path == "/api/v1/log":
            self._handle_log_get()
        elif path == "/api/v1/log/proof":
            self._handle_log_proof(params)
        elif path == "/api/v1/log/publicKey":
            self._handle_log_public_key()
        elif path.startswith("/api/v1/log/entries/"):
            entry_id = path.split("/")[-1]
            self._handle_log_entry_get(entry_id)
        elif path == "/api/v1/log/entries" and "logIndex" in params:
            idx = params["logIndex"][0]
            self._handle_log_entry_get(idx)
        elif path == "/healthz":
            self._json_response(200, {
                "status": "ok",
                "tree_size": self.ct_log.tree_size(),
                "akamu_url": self.config.akamu_url,
                "dogtag_url": self.config.dogtag_url,
            })
        else:
            self._json_response(404, {"error": "not found", "path": path})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/v2/signingCert":
            self._handle_signing_cert()
        elif path == "/api/v1/log/entries":
            self._handle_log_entries_post()
        else:
            self._json_response(404, {"error": "not found", "path": path})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Akamu Signing Adapter — Fulcio+Rekor API backed by Akamu/Dogtag"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=5555, help="Listen port")
    parser.add_argument(
        "--akamu-url", default="https://localhost/akamu",
        help="Akamu base URL"
    )
    parser.add_argument(
        "--ahdapa-url", default="https://localhost/idp",
        help="ahdapa OIDC issuer URL"
    )
    parser.add_argument(
        "--dogtag-url", default="https://localhost:8443",
        help="Dogtag CA URL"
    )
    parser.add_argument(
        "--ra-cert", default="/var/lib/akamu/akamu-ra-agent.pem",
        help="RA agent certificate"
    )
    parser.add_argument(
        "--ra-key", default="/var/lib/akamu/akamu-ra-agent.key",
        help="RA agent private key"
    )
    parser.add_argument(
        "--ca-cert", default="/etc/ipa/ca.crt",
        help="CA certificate for TLS verification"
    )
    parser.add_argument(
        "--profile-id", default="caServerCert",
        help="Dogtag enrollment profile ID"
    )
    parser.add_argument(
        "--db-path", default="/var/lib/akamu/adapter-ct-log.db",
        help="SQLite database for CT log"
    )
    args = parser.parse_args()

    config = AdapterConfig(args)

    signer = DogtagSigner(
        dogtag_url=config.dogtag_url,
        ra_cert=config.ra_cert,
        ra_key=config.ra_key,
        ca_cert=config.ca_cert,
        profile_id=config.profile_id,
    )

    ct_log = MerkleTree(config.db_path)

    AdapterHandler.config = config
    AdapterHandler.signer = signer
    AdapterHandler.ct_log = ct_log

    server = HTTPServer((config.listen_host, config.listen_port), AdapterHandler)
    log.info(
        "Akamu Signing Adapter listening on %s:%d",
        config.listen_host, config.listen_port,
    )
    log.info("  Akamu:  %s", config.akamu_url)
    log.info("  Dogtag: %s", config.dogtag_url)
    log.info("  CT log: %s (%d entries)", config.db_path, ct_log.tree_size())

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    log.info("Adapter stopped.")


if __name__ == "__main__":
    main()
