import os
import asyncio
import vt
import logging

logger = logging.getLogger()

class VirusTotalAPI:

    @classmethod
    async def create(cls, api_key: str | None = None) -> "VirusTotalAPI":
        self = cls(api_key)
        return self

    def __init__(self, api_key: str | None = None) -> None:
        logger.info("VirusTotal Client is initialized.")
        _api_key = api_key or os.getenv("VT_API_KEY")
        if not _api_key:
            raise ValueError("API key is required. Please set the VT_API_KEY environment variable or pass it as an argument.")
        self._client = vt.Client(_api_key)

    async def close(self) -> None:
        logger.info("VirusTotal Client is closed.")
        await self._client.close_async()

    async def get_ip_reputation(self, ip_address: str) -> dict | None:
        """
        get reputation of an IP address.

        Args:
            ip_address (str): IP address to check reputation for.

        Returns:
            dict: Reputation stats, e.g. {
                'harmless': 85,
                'malicious': 3,
                'suspicious': 1,
                ...
            }
            or None if an error occurs.
        """
        if self._client is None:
            raise RuntimeError("VirusTotal client is not initialized. Please use 'async with VirusTotalAPI() as vt_api:' context manager.")

        try:
            ip_obj = await self._client.get_object_async(f"/ip_addresses/{ip_address}")
            return ip_obj.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching ip reputation: {e}")
            return None

    async def get_domain_reputation(self, domain: str) -> dict | None:
        """
        Get reputation of a domain.

        Args:
            domain (str): Domain name to check reputation for.

        Returns:
            dict: Reputation stats, e.g. {
                'harmless': 85,
                'malicious': 3,
                'suspicious': 1,
                ...
            }
            or None if an error occurs.
        """
        if self._client is None:
            raise RuntimeError("VirusTotal client is not initialized. Please use 'async with VirusTotalAPI() as vt_api:' context manager.")
        try:
            domain_obj = await self._client.get_object_async(f"/domains/{domain}")
            return domain_obj.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching domain reputation: {e}")
            return None
    
    async def get_file_reputation(self, file_hash: str) -> dict | None:
        if self._client is None:
            raise RuntimeError("VirusTotal client is not initialized. Please use 'async with VirusTotalAPI() as vt_api:' context manager.")
        try:
            file_obj = await self._client.get_object_async(f"/files/{file_hash}")
            return file_obj.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching file reputation: {e}")
            return None
    
    async def get_url_reputation(self, url: str) -> dict | None:
        if self._client is None:
            raise RuntimeError("VirusTotal client is not initialized. Please use 'async with VirusTotalAPI() as vt_api:' context manager.")
        try:
            url_id = vt.url_id(url)
            url_obj = await self._client.get_object_async(f"/urls/{url_id}")
            return url_obj.last_analysis_stats
        except vt.error.APIError as e:
            print(f"Error fetching URL reputation: {e}")
            return None

# -- demo usage --
async def main():
    async with VirusTotalAPI() as vt_api:
        stats = await vt_api.get_ip_reputation("8.8.8.8")
        print(stats)

if __name__ == "__main__":
    asyncio.run(main())
