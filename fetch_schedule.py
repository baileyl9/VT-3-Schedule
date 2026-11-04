
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote

import requests
import certifi

# CNATRA VT-3 schedule location
BASE = "https://www.cnatra.navy.mil/scheds/TW5/SQ-VT-3/"

# Get tomorrow's date in Central Time
today = datetime.now(ZoneInfo("America/Chicago")).date()
flight_date = today + timedelta(days=1)

# Build the PDF URL
filename = f"!{flight_date:%Y-%m-%d}!VT-3!Frontpage.pdf"
url = BASE + quote(filename, safe="!")

print(f"Checking VT-3 schedule for {flight_date}")
print(f"URL: {url}")

try:
    response = requests.get(
        url,
        headers={
            "User-Agent": "VT3ScheduleChecker/1.0"
        },
        timeout=30,
        verify=certifi.where()
    )

    response.raise_for_status()

    pdf = response.content

    if not pdf.startswith(b"%PDF-"):
        raise ValueError("Response is not a valid PDF")

    print("SUCCESS: CNATRA PDF retrieved")
    print(f"Filename: {filename}")
    print(f"PDF size: {len(pdf)} bytes")

except requests.exceptions.SSLError as e:
    print("ERROR: SSL certificate verification failed.")
    print("CNATRA may have an incomplete certificate chain.")
    print(str(e))
    raise

except requests.exceptions.RequestException as e:
    print(f"ERROR: Unable to retrieve schedule: {e}")
    raise

except ValueError as e:
    print(f"ERROR: {e}")
    raise
