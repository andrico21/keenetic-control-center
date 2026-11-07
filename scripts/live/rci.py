#!/usr/bin/env python3
"""Minimal NDW2 RCI client for the live smoke scripts (stdlib only).

    rci.py <url> <login> <password-file> serial          prints the show identification serial
    rci.py <url> <login> <password-file> parse <line>    sends one full-path CLI line

Only `x-ndw2-interactive` routers are supported; an NDW4-only router fails with a clear
message (use the Rust live gate instead). The password never leaves this process.
"""

import hashlib
import http.cookiejar
import json
import pathlib
import sys
import urllib.error
import urllib.request


def main() -> int:
    url, login, password_file, command, *rest = sys.argv[1:]
    password = pathlib.Path(password_file).read_text().rstrip("\r\n")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    try:
        opener.open(f"{url}/auth", timeout=20)
        return fail("the router accepted an unauthenticated /auth")
    except urllib.error.HTTPError as challenge:
        realm = challenge.headers.get("x-ndm-realm")
        nonce = challenge.headers.get("x-ndm-challenge")
    if not realm or not nonce:
        return fail("no x-ndw2-interactive challenge (NDW4-only router?)")
    ha1 = hashlib.md5(f"{login}:{realm}:{password}".encode()).hexdigest()
    answer = hashlib.sha256((nonce + ha1).encode()).hexdigest()
    post(opener, f"{url}/auth", {"login": login, "password": answer})
    if command == "serial":
        identification = json.load(opener.open(f"{url}/rci/show/identification", timeout=20))
        print(identification.get("serial", ""))
        return 0
    if command == "parse" and len(rest) == 1:
        reply = post(opener, f"{url}/rci/", {"parse": rest[0]})
        statuses = reply.get("status", []) if isinstance(reply, dict) else []
        if any(status.get("status") == "error" for status in statuses):
            return fail(f"router refused: {rest[0]}")
        return 0
    return fail("usage: rci.py <url> <login> <password-file> serial | parse <line>")


def post(opener, url: str, body: dict):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    text = opener.open(request, timeout=20).read().decode()
    return json.loads(text) if text.strip() else {}


def fail(message: str) -> int:
    print(f"rci.py: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
