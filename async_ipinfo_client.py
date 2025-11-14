import aiohttp
import asyncio

class AsyncIPInfoClient:
    """
    Async IPInfo API client with:
    - concurrency limit
    - retry + exponential backoff
    - response cache
    - bulk fetching for unique IPs
    """

    def __init__(self, token, max_concurrency=5, retry=5):
        self.token = token
        self.max_concurrency = max_concurrency
        self.retry = retry
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.cache = {}

    async def fetch_one(self, ip, session):
        # Cache hit
        if ip in self.cache:
            return self.cache[ip]

        url = f"https://ipinfo.io/lite/{ip}?token={self.token}"

        for attempt in range(self.retry):
            async with self.semaphore:
                try:
                    async with session.get(url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            self.cache[ip] = data
                            return data

                        # common rate limit responses
                        if resp.status in (429, 443):
                            await asyncio.sleep(2 ** attempt)
                            continue

                        return None
                except Exception:
                    await asyncio.sleep(2 ** attempt)

        return None

    async def fetch_bulk(self, ip_list):
        """
        Fetch for all unique IPs asynchronously.
        Returns dict: {ip: result_dict_or_None}
        """

        unique_ips = list(set(ip_list))

        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_one(ip, session) for ip in unique_ips]
            results = await asyncio.gather(*tasks)

        return dict(zip(unique_ips, results))
