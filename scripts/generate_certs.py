#!/usr/bin/env python3
"""
Certificate & Key Generation Script
======================================
Generates:
  1. Ed25519 signing key pair (for token signing)
  2. Self-signed CA certificate
  3. Server TLS certificate signed by CA
  4. Client mTLS certificate signed by CA

Usage:
  python generate_certs.py [--output-dir ./certs]
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
except ImportError:
    print("ERROR: Install cryptography: pip install cryptography")
    sys.exit(1)

try:
    from nacl.signing import SigningKey
except ImportError:
    print("ERROR: Install PyNaCl: pip install pynacl")
    sys.exit(1)


def generate_ed25519_keypair(output_dir: Path) -> None:
    """Generate Ed25519 signing key pair for token signing."""
    print("[*] Generating Ed25519 token signing key pair...")
    sk = SigningKey.generate()
    vk = sk.verify_key

    priv_path = output_dir / "ed25519.key"
    pub_path = output_dir / "ed25519.pub"

    priv_path.write_bytes(sk.encode())
    pub_path.write_text(vk.encode().hex())

    print(f"    Private key: {priv_path}")
    print(f"    Public key:  {pub_path}")
    print(f"    Public hex:  {vk.encode().hex()[:32]}...")


def generate_ca(output_dir: Path, days: int = 3650) -> tuple:
    """Generate self-signed CA certificate."""
    print("[*] Generating CA certificate...")

    ca_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GameStore Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "GameStore Root CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write CA
    ca_key_path = output_dir / "ca.key"
    ca_cert_path = output_dir / "ca.crt"

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"    CA key:  {ca_key_path}")
    print(f"    CA cert: {ca_cert_path}")

    return ca_key, ca_cert


def generate_server_cert(output_dir: Path, ca_key, ca_cert, days: int = 365) -> None:
    """Generate server TLS certificate signed by CA."""
    print("[*] Generating server TLS certificate...")

    server_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GameStore"),
        x509.NameAttribute(NameOID.COMMON_NAME, "auth.gamestore.local"),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("auth.gamestore.local"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_cert_sign=False, crl_sign=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key_path = output_dir / "server.key"
    server_cert_path = output_dir / "server.crt"

    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"    Server key:  {server_key_path}")
    print(f"    Server cert: {server_cert_path}")


def generate_client_cert(
    output_dir: Path, ca_key, ca_cert,
    common_name: str = "gamestore-client", days: int = 90
) -> None:
    """Generate client mTLS certificate signed by CA."""
    print(f"[*] Generating client mTLS certificate (CN={common_name})...")

    client_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GameStore"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_cert_sign=False, crl_sign=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    client_key_path = output_dir / f"client-{common_name}.key"
    client_cert_path = output_dir / f"client-{common_name}.crt"

    client_key_path.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    client_cert_path.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))

    print(f"    Client key:  {client_key_path}")
    print(f"    Client cert: {client_cert_path}")


def main():
    import ipaddress  # noqa: F811
    # Make ipaddress available to generate_server_cert
    import builtins
    builtins.ipaddress = ipaddress

    parser = argparse.ArgumentParser(description="Generate GameStore auth certificates")
    parser.add_argument("--output-dir", default="./certs", help="Output directory")
    parser.add_argument("--client-cn", default="gamestore-client", help="Client cert CN")
    parser.add_argument("--ca-days", type=int, default=3650, help="CA validity (days)")
    parser.add_argument("--server-days", type=int, default=365, help="Server cert validity")
    parser.add_argument("--client-days", type=int, default=90, help="Client cert validity")
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    generate_ed25519_keypair(out)
    ca_key, ca_cert = generate_ca(out, days=args.ca_days)
    generate_server_cert(out, ca_key, ca_cert, days=args.server_days)
    generate_client_cert(out, ca_key, ca_cert, common_name=args.client_cn, days=args.client_days)

    print("\n[✓] All certificates generated successfully!")
    print(f"    Output directory: {out.resolve()}")
    print("\n    IMPORTANT: Keep ca.key and ed25519.key SECRET.")
    print("    Distribute ca.crt and client certs to authorized clients.")


if __name__ == "__main__":
    import ipaddress
    main()
