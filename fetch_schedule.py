
import io
import json
import os
import re
import socket
import ssl
import tempfile

from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlparse
from zoneinfo import ZoneInfo

import certifi
import pdfplumber
import requests

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID


HOST = "www.cnatra.navy.mil"
BASE = f"https://{HOST}/scheds/TW5/SQ-VT-3/"

# Default name for automatic searches.
# Can be changed when manually running GitHub Actions.
SEARCH_NAME = os.environ.get(
    "SEARCH_NAME", "Logan Bailey"
).strip()


def get_intermediate():
    # Retrieve the server certificate to locate
    # its issuer. The PDF request itself uses
    # verified HTTPS.
    context = ssl._create_unverified_context()

    with socket.create_connection(
        (HOST, 443), timeout=20
    ) as sock:
        with context.wrap_socket(
            sock, server_hostname=HOST
        ) as tls:
            leaf_der = tls.getpeercert(
                binary_form=True
            )

    leaf = x509.load_der_x509_certificate(
        leaf_der
    )

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

        try:
            response = requests.get(
                url, timeout=20
            )
            response.raise_for_status()
            data = response.content

            try:
                certs = [
                    x509.load_der_x509_certificate(
                        data
                    )
                ]
            except ValueError:
                try:
                    certs = [
                        x509.load_pem_x509_certificate(
                            data
                        )
                    ]
                except ValueError:
                    certs = (
                        pkcs7.load_der_pkcs7_certificates(
                            data
                        )
                    )

            for cert in certs:
                if cert.subject == leaf.issuer:
                    print(
                        "Found matching issuer certificate"
                    )
                    return cert.public_bytes(
                        serialization.Encoding.PEM
                    )

        except (requests.RequestException, ValueError):
            continue

    raise RuntimeError(
        "Unable to retrieve issuer certificate"
    )


def name_variations(full_name):
    parts = full_name.upper().split()

    if len(parts) < 2:
        return [full_name.upper()]

    first = parts[0]
    last = parts[-1]

    return [
        f"{first} {last}",
        f"{last} {first}",
        f"{last}, {first}",
        f"{last}, {first[0]}",
        f"{last} {first[0]}",
        last
    ]


def matches_name(line, variations):
    text = re.sub(
        r"\s+", " ", line.upper()
    ).strip()

    return any(
        re.search(
            r"(?<![A-Z])"
            + re.escape(name)
            + r"(?![A-Z])",
            text
        )
        for name in variations
    )


def extract_schedule(pdf_bytes, search_name):
    variations = name_variations(search_name)
    matches = []

    with pdfplumber.open(
        io.BytesIO(pdf_bytes)
    ) as pdf:

        pages_read = len(pdf.pages)

        for page_number, page in enumerate(
            pdf.pages, 1
        ):
            text = page.extract_text() or ""
            lines = text.splitlines()

            for index, line in enumerate(lines):
                if matches_name(
                    line, variations
                ):
                    nearby = lines[
                        max(0, index - 1):
                        min(len(lines), index + 2)
                    ]

                    matches.append({
                        "page": page_number,
                        "line": line.strip(),
                        "context": "\n".join(nearby)
                    })

    return pages_read, matches


def main():
    now = datetime.now(
        ZoneInfo("America/Chicago")
    )

    flight_date = (
        now.date() + timedelta(days=1)
    )

    filename = (
        f"!{flight_date:%Y-%m-%d}"
        "!VT-3!Frontpage.pdf"
    )

    url = BASE + quote(
        filename, safe="!"
    )

    print("Checking VT-3 schedule")
    print("Flight date:", flight_date)
    print("Searching for:", SEARCH_NAME)

    with tempfile.TemporaryDirectory() as folder:
        bundle = Path(folder) / "trusted.pem"

        bundle.write_bytes(
            Path(certifi.where()).read_bytes()
            + b"\n"
            + get_intermediate()
        )

        response = requests.get(
            url,
            timeout=30,
            verify=str(bundle)
        )
        response.raise_for_status()

        pdf_bytes = response.content

        if not pdf_bytes.startswith(b"%PDF-"):
            raise ValueError(
                "CNATRA did not return a PDF"
            )

    print(
        "PDF downloaded:",
        len(pdf_bytes), "bytes"
    )

    pages_read, matches = extract_schedule(
        pdf_bytes, SEARCH_NAME
    )

    result = {
        "flight_date": str(flight_date),
        "search_name": SEARCH_NAME,
        "source_url": url,
        "retrieved_at": now.isoformat(),
        "pages_read": pages_read,
        "match_count": len(matches),
        "matches": matches
    }

    output = Path("schedule_results.json")

    output.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    print("PDF successfully downloaded and parsed")
    print("Pages:", pages_read)
    print("Matching lines:", len(matches))
    print("Saved:", output)

    for match in matches:
        print(
            f"Page {match['page']}: "
            f"{match['line']}"
        )

    if not matches:
        print(
            "No matching text found. "
            "Verify the PDF layout before "
            "concluding there are no events."
        )


if __name__ == "__main__":
    main()
