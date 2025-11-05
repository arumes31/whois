# utils/portscan.py
import socket
import time
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_exponential
import ipaddress
import logging

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Low-level TCP connect with retry
# ----------------------------------------------------------------------
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=3))
def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout, ConnectionRefusedError):
        return False


# ----------------------------------------------------------------------
# Public function: scan ports
# ----------------------------------------------------------------------
def scan_ports(target: str, ports: List[int]) -> Dict[str, Any]:
    """
    Scan a list of ports on *target*.
    Returns a dict with open ports, errors, and timing.
    """
    if not ports:
        return {"open": [], "closed": [], "error": "No ports supplied"}

    results = {"open": [], "closed": [], "timing": {}}
    start = time.monotonic()

    with ThreadPoolExecutor(max_workers=min(50, len(ports))) as exe:
        future_to_port = {exe.submit(_tcp_connect, target, p): p for p in ports}
        for fut in as_completed(future_to_port):
            port = future_to_port[fut]
            try:
                open_ = fut.result()
                (results["open"] if open_ else results["closed"]).append(port)
            except Exception as e:
                results.setdefault("error", []).append(f"Port {port}: {e}")

    results["elapsed"] = round(time.monotonic() - start, 3)
    logger.debug(f"Port scan on {target} completed in {results['elapsed']}s")
    return results