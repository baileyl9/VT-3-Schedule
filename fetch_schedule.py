
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
import requests

BASE = "https://www.cnatra.navy.mil/scheds/TW5/SQ-VT-3/"
today = datetime.now(ZoneInfo("America/Chicago")).date()
flight_date = today + timedelta(days=1)

filename = f"!{flight_date:%Y-%m-%d}!VT-3!Frontpage.pdf"
url = BASE + quote(filename, safe="!")

response = requests.get(
    url,
    headers={"User-Agent": "VT3ScheduleChecker/1.0"},
    timeout=30
)
response.raise_for_status()

pdf = response.content
if not pdf.startswith(b"%PDF-"):
    raise ValueError("Response is not a valid PDF")

print(f"Retrieved {filename}")
print(f"PDF size: {len(pdf)} bytes")
