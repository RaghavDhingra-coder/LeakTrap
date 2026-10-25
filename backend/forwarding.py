"""Reading a client address from X-Forwarded-For written by trusted proxies.

Kept free of other LeakTrace imports so any mode, including ingest, can load it
without loading account or session code.
"""

import ipaddress


def forwarded_client(x_forwarded_for: list[str], hops: int) -> str | None:
    """The client address in an X-Forwarded-For chain written by `hops` trusted proxies, or None.

    Each proxy appends the address it received the request from, so the client is
    `hops` entries from the right; anything further left was written by the client
    and can be forged. The chain is refused (None) if it is shorter than `hops` or
    if that entry or any entry to its right is not a plain IP address.
    """
    if hops < 1:
        return None
    entries = [entry.strip() for value in x_forwarded_for for entry in value.split(",")]
    if len(entries) < hops:
        return None
    try:
        trusted = [ipaddress.ip_address(entry) for entry in entries[-hops:]]
    except ValueError:
        return None
    return str(trusted[0])
