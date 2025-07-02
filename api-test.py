import vt
import os
import argparse

import vtapi

"""

This is a test script for the VirusTotal API.
I'd like to test the API key and ensure that it can fetch data correctly.
And I use the vt-py package to interact with the API.

will test the following API endpoints:
1. get reputation of an IP address
2. get reputation of a domain
3. get reputation of a file hash
4. get reputation of a URL
5. submit a file for analysis

and I store api_key in environment variable VT_API_KEY.
"""

def get_arguments():
    parser = argparse.ArgumentParser(description="VirusTotal API Test Script")
    parser.add_argument("type", choices=["ip", "domain", "file", "url"], help="Type of reputation to check")
    parser.add_argument("value", help="Value to check reputation for (IP, domain, file hash, or URL)")
    parser.add_argument("--api-key", help="API key for VirusTotal")
    return parser.parse_args()

if __name__ == "__main__":
    args = get_arguments()
    if args.api_key:
        vtapi.VirusTotalAPI.connect(api_key=args.api_key)
    else:
        vtapi.VirusTotalAPI.connect()
    vt_api = vtapi.VirusTotalAPI()
    if args.type == "ip":
        result = vt_api.get_ip_reputation(args.value)
    elif args.type == "domain":
        result = vt_api.get_domain_reputation(args.value)
    elif args.type == "file":
        result = vt_api.get_file_reputation(args.value)
    elif args.type == "url":
        result = vt_api.get_url_reputation(args.value)
    
    if result:
        print(f"Reputation for {args.value} ({args.type}): {result}")
    else:
        print(f"No reputation data found for {args.value} ({args.type}).")
    
    vtapi.VirusTotalAPI.close()
