"""Measure PhishGuard API latency and throughput.

Start the API first (same command as the Dockerfile):
    gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 app:app
Then:  python scripts/load_test.py data.csv
"""
import asyncio
import statistics
import sys
import time

import httpx
import pandas as pd

BASE = "http://localhost:5000"
urls = pd.read_csv(sys.argv[1])["url"].sample(3000, random_state=7).tolist()


def pct(xs, q):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(q * len(xs)))]


async def single(client, url, out):
    t = time.perf_counter(); r = await client.post(f"{BASE}/api/predict", json={"url": url})
    if r.status_code == 200: out.append((time.perf_counter() - t) * 1000)


async def run(concurrency, n):
    out = []
    async with httpx.AsyncClient(timeout=60) as c:
        for _ in range(20): await single(c, urls[0], [])  # warm-up
        sem = asyncio.Semaphore(concurrency)
        async def task(u):
            async with sem: await single(c, u, out)
        t = time.perf_counter(); await asyncio.gather(*(task(u) for u in urls[:n])); wall = time.perf_counter() - t
    return out, wall


async def batch(size, reps=5):
    times = []
    async with httpx.AsyncClient(timeout=300) as c:
        for i in range(reps):
            chunk = urls[i * size:(i + 1) * size]
            t = time.perf_counter(); r = await c.post(f"{BASE}/api/predict/batch", json={"urls": chunk}); r.raise_for_status()
            times.append(time.perf_counter() - t)
    return statistics.median(times)


async def main():
    lat, _ = await run(1, 300)
    print(f"Single URL, sequential: p50 {pct(lat, .5):.1f} ms, p95 {pct(lat, .95):.1f} ms")
    lat, wall = await run(8, 1500)
    print(f"Single URL, 8 concurrent clients: {len(lat) / wall:.0f} requests/sec, p50 {pct(lat, .5):.1f} ms, p95 {pct(lat, .95):.1f} ms")
    b = await batch(500)
    print(f"Batch of 500 URLs: {b:.2f} s median ({500 / b:.0f} URLs/sec)")

asyncio.run(main())
