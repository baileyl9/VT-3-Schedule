
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote, urlparse
from pathlib import Path
import socket
import ssl
import tempfile

import certifi
import requests
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.hazmat.primitives.serialization import pkcs7

HOST = "www.cnatra.navy.mil"
BASE = f"https://{HOST}/scheds/TW5/SQ-VT-3/"

def get_intermediate():
    # Retrieve the server's public certificate.
    context = ssl._create_unverified_context()
    with socket.create_connection((HOST, 443), timeout=20) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as tls:
            leaf_der = tls.getpeercert(binary_form=True)

    leaf = x509.load_der_x509_certificate(leaf_der)
    aia = leaf.extensions.get_extension_for_class(
        x509.AuthorityInformationAccess
    ).value

    urls = [
        entry.access_location.value
        for entry in aia
        if entry.access_method ==
        AuthorityInformationAccessOID.CA_ISSUERS
    ]

    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            continue

        print("Checking issuer certificate:", parsed.hostname)
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            data = response.content

            try:
                certificates = [
                    x509.load_der_x509_certificate(data)
                ]
            except ValueError:
                try:
                    certificates = [
                        x509.load_pem_x509_certificate(data)
                    ]
                except ValueError:
                    certificates = (
                        pkcs7.load_der_pkcs7_certificates(data)
                    )

            for cert in certificates:
                if cert.subject == leaf.issuer:
                    print("Found matching issuer certificate")
                    return cert.public_bytes(
                        encoding=__import__(
                            "cryptography.hazmat.primitives.serialization",
                            fromlist=["Encoding"]
                        ).Encoding.PEM
                    )
        except (requests.RequestException, ValueError) as error:
            print("Issuer retrieval failed:", error)

    raise RuntimeError("Could not retrieve matching issuer certificate")

today = datetime.now(ZoneInfo("America/Chicago")).date()
flight_date = today + timedelta(days=1)

filename = f"!{flight_date:%Y-%m-%d}!VT-3!Frontpage.pdf"
url = BASE + quote(filename, safe="!")

print("Checking VT-3 schedule:", flight_date)

with tempfile.TemporaryDirectory() as folder:
    bundle = Path(folder) / "trusted.pem"

    trusted_roots = Path(certifi.where()).read_bytes()
    intermediate = get_intermediate()
    bundle.write_bytes(
        trusted_roots + b"\n" + intermediate
    )

    response = requests.get(
        url,
        timeout=30,
        verify=str(bundle)
    )
    response.raise_for_status()

    if not response.content.startswith(b"%PDF-"):
        raise ValueError("CNATRA did not return a PDF")

    print("SUCCESS: CNATRA PDF retrieved")
    print("Filename:", filename)
    print("PDF size:", len(response.content))
