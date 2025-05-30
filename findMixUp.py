#!/usr/bin/env python3
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

IGNORE_OIDS = {
    "1.3.6.1.4.1.11129.2.4.2",  # SCT
    "1.3.6.1.4.1.11129.2.4.3",  # Poison
}

def load_cert(path):
    with open(path, "rb") as f:
        data = f.read()
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except ValueError:
            return x509.load_der_x509_certificate(data, default_backend())

def describe_extensions(cert):
    ext_list = []
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if oid not in IGNORE_OIDS:
            try:
                val_bytes = ext.value.public_bytes()
            except Exception:
                val_bytes = bytes(str(ext.value), 'utf-8')
            ext_list.append((oid, len(val_bytes)))
    return ext_list

def compare_extensions(desc1, desc2):
    order1 = [oid for oid, _ in desc1]
    order2 = [oid for oid, _ in desc2]

    print(f"\n{'Extension':<40} {'OID':<40} {'Cert1 Bytes':>12} {'Cert2 Bytes':>12}  Reason")
    print("-" * 120)

    all_oids = sorted(set(order1) | set(order2))
    for oid in all_oids:
        c1_len = next((b for o, b in desc1 if o == oid), None)
        c2_len = next((b for o, b in desc2 if o == oid), None)
        reason = "✅ Match"

        if c1_len is None or c2_len is None:
            reason = "❌ Missing in one cert"
        elif c1_len != c2_len:
            reason = "❌ Byte length mismatch"
        else:
            pos1 = order1.index(oid)
            pos2 = order2.index(oid)
            if pos1 != pos2:
                reason = "❌ Different order"

        name = oid if oid.startswith("1.") else x509.ObjectIdentifier(oid)._name
        c1_display = c1_len if c1_len is not None else "-"
        c2_display = c2_len if c2_len is not None else "-"
        print(f"{name:<40} {oid:<40} {c1_display:>12} {c2_display:>12}  {reason}")

def compare_fields(cert1, cert2):
    def get_pubkey_bytes(cert):
        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    fields = [
        ("Version", str(cert1.version), str(cert2.version)),
        ("Serial Number", hex(cert1.serial_number), hex(cert2.serial_number)),
        ("Signature Algorithm", str(cert1.signature_algorithm_oid), str(cert2.signature_algorithm_oid)),
        ("Issuer", cert1.issuer.rfc4514_string(), cert2.issuer.rfc4514_string()),
        ("Validity (notBefore)", str(cert1.not_valid_before_utc), str(cert2.not_valid_before_utc)),
        ("Validity (notAfter)", str(cert1.not_valid_after_utc), str(cert2.not_valid_after_utc)),
        ("Subject", cert1.subject.rfc4514_string(), cert2.subject.rfc4514_string()),
        ("Public Key DER", get_pubkey_bytes(cert1).hex(), get_pubkey_bytes(cert2).hex()),
    ]

    print(f"{'Field':<30} {'Cert1':<45} {'Cert2':<45}  Match?")
    print("-" * 130)

    for label, val1, val2 in fields:
        match = "✅" if val1 == val2 else "❌"
        print(f"{label:<30} {val1[:44]:<45} {val2[:44]:<45}  {match}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cert1", help="First certificate file (PEM or DER)")
    parser.add_argument("cert2", help="Second certificate file (PEM or DER)")
    args = parser.parse_args()

    cert1 = load_cert(args.cert1)
    cert2 = load_cert(args.cert2)

    print("=== Field Comparison ===")
    compare_fields(cert1, cert2)

    print("\n=== Extension Comparison ===")
    desc1 = describe_extensions(cert1)
    desc2 = describe_extensions(cert2)
    compare_extensions(desc1, desc2)

if __name__ == "__main__":
    main()
