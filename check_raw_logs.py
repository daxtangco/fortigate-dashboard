#!/usr/bin/env python3
import requests
import json
from getpass import getpass

API_URL = "https://157.245.51.118"

# Disable SSL warnings for self-signed certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Login
username = input("Username (default: admin): ").strip() or "admin"
password = getpass("Password: ")

print("\n🔐 Logging in...")
login_response = requests.post(
    f"{API_URL}/api/login",
    data={"username": username, "password": password},
    verify=False
)

if login_response.status_code != 200:
    print("❌ Login failed!")
    print(login_response.text)
    exit(1)

token = login_response.json()["access_token"]
print("✅ Login successful!")

# Fetch raw logs
print("\n📋 Fetching raw logs...\n")
headers = {"Authorization": f"Bearer {token}"}
logs_response = requests.get(
    f"{API_URL}/api/debug/raw-logs?limit=3",
    headers=headers,
    verify=False
)

if logs_response.status_code == 200:
    data = logs_response.json()
    print("=" * 80)
    print("RAW LOG DATA (last 3 logs)")
    print("=" * 80)

    for i, log in enumerate(data["logs"], 1):
        print(f"\n--- LOG #{i} ---")
        print(json.dumps(log, indent=2, sort_keys=True))
        print("\nAvailable fields:")
        for key in sorted(log.keys()):
            value = log[key]
            if len(str(value)) > 50:
                value = str(value)[:50] + "..."
            print(f"  • {key}: {value}")
else:
    print("❌ Failed to fetch logs!")
    print(logs_response.text)
