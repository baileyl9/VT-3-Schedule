
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
TIMEZONE = ZoneInfo("America/Chicago")
DEFAULT_NAME = "Logan Bailey"
SEARCH_NAME = os.getenv("SEARCH_NAME", DEFAULT_NAME).strip()
SCHEDULE_DATE = os.getenv("SCHEDULE_DATE", "").strip()
OUTPUT_DIR = Path("schedule_output")


def get_intermediate():
    # Discover the missing issuer certificate.
    # The actual PDF request still verifies TLS.
    context = ssl._create_unverified_context()

    with socket.create_connection(
        (HOST, 443), timeout=20
    ) as sock:
        with context.wrap_socket(
            sock, server_hostname=HOST
        ) as tls:
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

        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            data = response.content

            try:
                certs = [
                    x509.load_der_x509_certificate(data)
                ]
            except ValueError:
                try:
                    certs = [
                        x509.load_pem_x509_certificate(data)
                    ]
                except ValueError:
                    certs = (
                        pkcs7.load_der_pkcs7_certificates(data)
                    )

            for cert in certs:
                if cert.subject == leaf.issuer:
                    print("Found matching issuer certificate")
                    return cert.public_bytes(
                        serialization.Encoding.PEM
                    )

        except (requests.RequestException, ValueError):
            continue

    raise RuntimeError(
        "Unable to retrieve CNATRA issuer certificate"
    )


def download_pdf(url):
    with tempfile.TemporaryDirectory() as folder:
        bundle = Path(folder) / "trusted.pem"

        bundle.write_bytes(
            Path(certifi.where()).read_bytes()
            + b"\n"
            + get_intermediate()
        )

        response = requests.get(
            url, timeout=45, verify=str(bundle)
        )
        response.raise_for_status()

        data = response.content

        if not data.startswith(b"%PDF-"):
            raise ValueError("CNATRA did not return a PDF")

        return data


def normalize(text):
    return re.sub(r"\s+", " ", str(text or "")).strip()


def person_variations(name):
    parts = normalize(name).upper().split()

    if len(parts) < 2:
        return [normalize(name).upper()]

    first, last = parts[0], parts[-1]

    return [
        f"{first} {last}",
        f"{last}, {first}",
        f"{last} {first}",
        f"{last}, {first[0]}",
        f"{last} {first[0]}"
    ]


def contains_person(text, name):
    text = normalize(text).upper()

    for variation in person_variations(name):
        pattern = (
            r"(?<![A-Z])"
            + re.escape(variation)
            + r"(?![A-Z])"
        )
        if re.search(pattern, text):
            return True

    return False


def detect_section(text, previous):
    value = normalize(text).upper()

    if "FLIGHT (FLY EVENT) SCHEDULE" in value:
        return "flight"

    if "SIMULATOR (SIM EVENT) SCHEDULE" in value:
        return "simulator"

    if value == "GROUND EVENTS":
        return "ground"

    if value == "MEETINGS":
        return "meetings"

    if value == "MIL DUTY":
        return "military_duty"

    if value == "SELECTION":
        return "selection"

    if value == "FLT STBY":
        return "flight_standby"

    if value == "EXAM":
        return "exams"

    if value == "CAI":
        return "computer_assisted_instruction"

    if value == "DUTY/WATCH":
        return "duty_watch"

    return previous


def clean_table(table):
    rows = []

    for row in table:
        if not row:
            continue

        cells = [
            normalize(cell)
            for cell in row
        ]

        if any(cells):
            rows.append(cells)

    return rows


def extract_schedule(data):
    pages = []
    tables = []
    records = []
    full_text = []
    current_section = "general"

    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page_number, page in enumerate(pdf.pages, 1):
            text = page.extract_text(
                layout=False
            ) or ""

            lines = text.splitlines()
            full_text.append(
                f"\n===== PAGE {page_number} =====\n{text}"
            )

            page_info = {
                "page": page_number,
                "text": text,
                "lines": []
            }

            for line_number, line in enumerate(lines, 1):
                current_section = detect_section(
                    line, current_section
                )

                entry = {
                    "page": page_number,
                    "line_number": line_number,
                    "section": current_section,
                    "text": normalize(line)
                }

                page_info["lines"].append(entry)

                if entry["text"]:
                    records.append(entry)

            pages.append(page_info)

            # Preserve original table cells and row order.
            for table_number, table in enumerate(
                page.extract_tables(), 1
            ):
                rows = clean_table(table)

                if not rows:
                    continue

                table_record = {
                    "page": page_number,
                    "table_number": table_number,
                    "rows": rows
                }

                tables.append(table_record)

    return {
        "pages": pages,
        "tables": tables,
        "records": records,
        "full_text": "\n".join(full_text)
    }


def find_person(schedule, name):
    matches = []

    for record in schedule["records"]:
        if contains_person(record["text"], name):
            matches.append({
                "source": "text",
                **record
            })

    for table in schedule["tables"]:
        rows = table["rows"]

        for index, row in enumerate(rows):
            if any(
                contains_person(cell, name)
                for cell in row
            ):
                matches.append({
                    "source": "table",
                    "page": table["page"],
                    "table_number": table["table_number"],
                    "row_number": index + 1,
                    "cells": row
                })

    return matches


def main():
    now = datetime.now(TIMEZONE)

    if SCHEDULE_DATE:
        flight_date = datetime.strptime(
            SCHEDULE_DATE, "%Y-%m-%d"
        ).date()
    else:
        flight_date = (
            now.date() + timedelta(days=1)
        )

    filename = (
        f"!{flight_date:%Y-%m-%d}"
        "!VT-3!Frontpage.pdf"
    )

    url = BASE + quote(filename, safe="!")

    OUTPUT_DIR.mkdir(
        parents=True, exist_ok=True
    )

    print("VT-3 FULL SCHEDULE EXTRACTION")
    print("Date:", flight_date)
    print("URL:", url)
    print("Default search:", SEARCH_NAME)

    pdf_bytes = download_pdf(url)

    print(
        "Downloaded PDF:",
        len(pdf_bytes), "bytes"
    )

    schedule = extract_schedule(pdf_bytes)

    matches = find_person(
        schedule, SEARCH_NAME
    )

    metadata = {
        "squadron": "VT-3",
        "schedule_date": str(flight_date),
        "source_url": url,
        "retrieved_at": now.isoformat(),
        "pages_read": len(schedule["pages"]),
        "table_count": len(schedule["tables"]),
        "text_record_count": len(schedule["records"])
    }

    complete = {
        "metadata": metadata,
        "pages": schedule["pages"],
        "tables": schedule["tables"],
        "records": schedule["records"]
    }

    search_results = {
        "metadata": metadata,
        "search_name": SEARCH_NAME,
        "match_count": len(matches),
        "matches": matches
    }

    (OUTPUT_DIR / "full_schedule.json").write_text(
        json.dumps(complete, indent=2),
        encoding="utf-8"
    )

    (OUTPUT_DIR / "full_schedule.txt").write_text(
        schedule["full_text"],
        encoding="utf-8"
    )

    (OUTPUT_DIR / "schedule_results.json").write_text(
        json.dumps(search_results, indent=2),
        encoding="utf-8"
    )

    # Also retain the original PDF for verification.
    (OUTPUT_DIR / "original_schedule.pdf").write_bytes(
        pdf_bytes
    )

    print("SUCCESS: Full schedule extracted")
    print("Pages:", metadata["pages_read"])
    print("Tables:", metadata["table_count"])
    print("Text records:", metadata["text_record_count"])
    print("Name matches:", len(matches))
    print("Output folder:", OUTPUT_DIR)

    for match in matches:
        if match["source"] == "text":
            print(
                f"Page {match['page']}: "
                f"{match['text']}"
            )
        else:
            print(
                f"Page {match['page']} table row: "
                + " | ".join(match["cells"])
            )


if __name__ == "__main__":
    main()
