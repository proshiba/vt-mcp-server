import vt
import os

"""
This is a wrapper script of the VirusTotal API.
It provides methods to fetch reputation data for IP addresses, domains, file hashes, and URLs.

It uses the vt-py package to interact with the API.
The API key should be stored in the environment variable VT_API_KEY.
"""

class VirusTotalAPI(object):
    API_OBJ = None
    @classmethod
    def connect(cls, api_key=None):
        """Set the API key for VirusTotal."""
        if cls.API_OBJ is not None:
            raise RuntimeError("API already connected. Please disconnect before reconnecting.")
        if api_key is None:
            api_key = os.getenv("VT_API_KEY")
            if not api_key:
                raise ValueError("Please set the VT_API_KEY environment variable.")
        cls.API_OBJ = vt.Client(api_key)

    @classmethod
    def close(cls):
        cls.API_OBJ.close()
        cls.API_OBJ = None

    def __init__(self):
        if self.API_OBJ is None:
            VirusTotalAPI.connect()

    def get_ip_reputation(self, ip_address):
        try:
            ip = self.API_OBJ.get_object(f"/ip_addresses/{ip_address}")
            return ip.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching IP reputation: {e}")
            return None
    
    def get_domain_reputation(self, domain):
        try:
            domain_obj = self.API_OBJ.get_object(f"/domains/{domain}")
            return domain_obj.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching domain reputation: {e}")
            return None
    
    def get_file_reputation(self, file_hash):
        try:
            file_obj = self.API_OBJ.get_object(f"/files/{file_hash}")
            return file_obj.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching file reputation: {e}")
            return None
    
    def get_url_reputation(self, url):
        try:
            url_id = vt.url_id(url)
            url_obj = self.API_OBJ.get_object(f"/urls/{url_id}")
            return url_obj.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching URL reputation: {e}")
            return None