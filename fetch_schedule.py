
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
TZ = ZoneInfo("America/Chicago")
OUTPUT = Path("schedules")
DEFAULT_NAME = "Logan Bailey"

SEARCH_NAME = (
    os.getenv("SEARCH_NAME") or DEFAULT_NAME
).strip()

DATE_OVERRIDE = os.getenv(
    "SCHEDULE_DATE", ""
).strip()

FORCE_CHECK = (
    os.getenv("FORCE_CHECK", "false").lower()
    == "true"
)


def get_intermediate():
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
                    x509.load_der_x509_certificate(data)
                ]
            except ValueError:
                try:
                    certs = [
                        x509.load_pem_x509_certificate(data)
                    ]
                except ValueError:
                    certs = (
                        pkcs7.load_der_pkcs7_certificates(
                            data
                        )
                    )

            for cert in certs:
                if cert.subject == leaf.issuer:
                    return cert.public_bytes(
                        serialization.Encoding.PEM
                    )

        except (requests.RequestException, ValueError):
            continue

    raise RuntimeError(
        "Unable to retrieve issuer certificate"
    )


def build_trust_bundle(folder):
    bundle = Path(folder) / "trusted.pem"

    bundle.write_bytes(
        Path(certifi.where()).read_bytes()
        + b"\n"
        + get_intermediate()
    )

    return bundle


def normalize(value):
    return re.sub(
        r"\s+", " ", str(value or "")
    ).strip()


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


def matches_person(text, name):
    text = normalize(text).upper()

    for variant in person_variations(name):
        pattern = (
            r"(?<![A-Z])"
            + re.escape(variant)
            + r"(?![A-Z])"
        )

        if re.search(pattern, text):
            return True

    return False


def target_dates(now):
    if DATE_OVERRIDE:
        return [
            datetime.strptime(
                DATE_OVERRIDE, "%Y-%m-%d"
            ).date()
        ]

    # Monday through Thursday: tomorrow.
    if now.weekday() in (0, 1, 2, 3):
        return [
            now.date() + timedelta(days=1)
        ]

    # Friday: Saturday, Sunday and Monday.
    if now.weekday() == 4:
        return [
            now.date() + timedelta(days=days)
            for days in (1, 2, 3)
        ]

    return []


def within_check_window(now):
    if DATE_OVERRIDE:
        return True

    if now.weekday() >= 5:
        return False

    minutes = now.hour * 60 + now.minute

    return 13 * 60 <= minutes <= 20 * 60


def extract_pdf(data):
    pages = []
    tables = []
    records = []
    full_text = []

    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page_num, page in enumerate(
            pdf.pages, 1
        ):
            text = page.extract_text() or ""

            pages.append({
                "page": page_num,
                "text": text
            })

            full_text.append(
                f"===== PAGE {page_num} =====\n{text}"
            )

            for line_num, line in enumerate(
                text.splitlines(), 1
            ):
                if normalize(line):
                    records.append({
                        "page": page_num,
                        "line_number": line_num,
                        "text": normalize(line)
                    })

            for table_num, table in enumerate(
                page.extract_tables(), 1
            ):
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

                if rows:
                    tables.append({
                        "page": page_num,
                        "table_number": table_num,
                        "rows": rows
                    })

    if not pages:
        raise ValueError("PDF has no pages")

    if not records:
        raise ValueError(
            "PDF contains no extractable text"
        )

    return {
        "pages": pages,
        "tables": tables,
        "records": records,
        "full_text": "\n\n".join(full_text)
    }


def search_schedule(schedule, name):
    matches = []

    for record in schedule["records"]:
        if matches_person(record["text"], name):
            matches.append({
                "source": "text",
                **record
            })

    for table in schedule["tables"]:
        for index, row in enumerate(
            table["rows"], 1
        ):
            if any(
                matches_person(cell, name)
                for cell in row
            ):
                matches.append({
                    "source": "table",
                    "page": table["page"],
                    "table_number": table["table_number"],
                    "row_number": index,
                    "cells": row
                })

    return matches


def check_date(day, session, bundle, now):
    date_string = day.isoformat()
    folder = OUTPUT / date_string
    status_file = folder / "status.json"

    if (
        not FORCE_CHECK
        and status_file.exists()
        and (folder / "full_schedule.json").exists()
        and (folder / "original_schedule.pdf").exists()
    ):
        try:
            old = json.loads(
                status_file.read_text(
                    encoding="utf-8"
                )
            )
            if old.get("status") == "downloaded":
                print(
                    f"SKIPPED {date_string}: "
                    "already downloaded"
                )
                return "already_downloaded"
        except (OSError, ValueError):
            pass

    filename = (
        f"!{date_string}!VT-3!Frontpage.pdf"
    )

    url = BASE + quote(filename, safe="!")

    print(f"Checking {date_string}")
    print(f"URL: {url}")

    try:
        response = session.get(
            url,
            timeout=45,
            verify=str(bundle)
        )

        if response.status_code in (404, 410):
            print(
                f"NOT PUBLISHED: {date_string}"
            )
            return "not_published"

        response.raise_for_status()
        data = response.content

        if not data.startswith(b"%PDF-"):
            print(
                f"NOT READY: {date_string}, "
                "response is not a PDF"
            )
            return "not_ready"

        schedule = extract_pdf(data)

    except (
        requests.RequestException,
        ValueError,
        OSError,
        Exception
    ) as error:
        # Do not record a successful download.
        # A later run can retry.
        print(
            f"RETRY NEEDED: {date_string}: "
            f"{type(error).__name__}: {error}"
        )
        return "retry_needed"

    metadata = {
        "squadron": "VT-3",
        "schedule_date": date_string,
        "source_url": url,
        "retrieved_at": now.isoformat(),
        "pages_read": len(schedule["pages"]),
        "table_count": len(schedule["tables"]),
        "text_record_count": len(
            schedule["records"]
        )
    }

    complete = {
        "metadata": metadata,
        "pages": schedule["pages"],
        "tables": schedule["tables"],
        "records": schedule["records"]
    }

    matches = search_schedule(
        schedule, SEARCH_NAME
    )

    results = {
        "metadata": metadata,
        "search_name": SEARCH_NAME,
        "match_count": len(matches),
        "matches": matches
    }

    folder.mkdir(
        parents=True, exist_ok=True
    )

    (folder / "full_schedule.json").write_text(
        json.dumps(complete, indent=2),
        encoding="utf-8"
    )

    (folder / "full_schedule.txt").write_text(
        schedule["full_text"],
        encoding="utf-8"
    )

    (folder / "schedule_results.json").write_text(
        json.dumps(results, indent=2),
        encoding="utf-8"
    )

    (folder / "original_schedule.pdf").write_bytes(
        data
    )

    status = {
        "status": "downloaded",
        **metadata
    }

    status_file.write_text(
        json.dumps(status, indent=2),
        encoding="utf-8"
    )

    print(
        f"DOWNLOADED: {date_string} "
        f"({len(schedule['pages'])} pages, "
        f"{len(matches)} name matches)"
    )

    return "downloaded"


def main():
    now = datetime.now(TZ)

    print("VT-3 SCHEDULE MONITOR")
    print("Local time:", now.isoformat())
    print("Default search:", SEARCH_NAME)

    if not within_check_window(now):
        print(
            "Outside 1300-2000 Central "
            "weekday monitoring window"
        )
        return

    dates = target_dates(now)

    if not dates:
        print("No dates to check today")
        return

    outcomes = {}

    with tempfile.TemporaryDirectory() as temp:
        bundle = build_trust_bundle(temp)

        with requests.Session() as session:
            for day in dates:
                outcome = check_date(
                    day, session, bundle, now
                )
                outcomes[day.isoformat()] = outcome

    print("CHECK SUMMARY")
    print(json.dumps(outcomes, indent=2))


if __name__ == "__main__":
    main()
