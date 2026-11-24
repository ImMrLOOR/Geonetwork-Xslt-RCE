# GeoNetwork formatter RCE lab (CVE-2026-58400)

A private-network educational reproduction of the GeoNetwork XSLT formatter RCE. It is intended for a disposable GeoNetwork lab that you control, including an assigned CTF/HTB lab target where testing is permitted.

## Safety and scope

- The script requires an explicit target URL and accepts only private IPv4 addresses. It rejects public IPs and hostnames.
- It runs only the fixed command `id`; it has no command-line command input, shell, reverse connection, or file read/write feature.
- The vulnerable formatter upload issue and the unsafe XSLT execution issue are separate advisories. This lab helper exercises the formatter flow only against a local installation.
- Do not expose a vulnerable lab to the internet. Use a throwaway VM/container and remove it after the exercise.

## Prerequisites

- A disposable GeoNetwork 4.4.11 lab (or another version explicitly known to be vulnerable).
- A record UUID in that lab.
- Python 3 and `curl` available on the machine running the script.
- Network access to the web port of your assigned lab target.

## Run

```powershell
python .\geonetwork_formatter_rce.py --base-url http://10.10.10.5:8080/geonetwork --uuid YOUR-RECORD-UUID
```

If your local port differs:

```powershell
python .\geonetwork_formatter_rce.py --base-url http://10.10.10.5:8081/geonetwork --uuid YOUR-RECORD-UUID
```

Successful execution prints the GeoNetwork process identity. Replace the example address and port with the private address and service port assigned to your lab. The script creates a temporary formatter and cookie jar and removes its temporary files when it exits. The uploaded formatter itself may remain in the lab; reset or discard the disposable instance after the exercise.

## Vulnerability notes

The GeoNetwork project's advisory says unsafe Saxon XSLT configuration permits Java extension functions in uploaded formatters and lists versions through 4.4.11 and 4.2.16 as affected; fixed releases are 4.4.12 and 4.2.17. The advisory describes formatter upload as requiring sufficient privileges. A separate authorization flaw can enable anonymous upload; do not conflate the two issues.

- [GeoNetwork advisory GHSA-x898-729x-cc3r / CVE-2026-58400](https://github.com/geonetwork/core-geonetwork/security/advisories/GHSA-x898-729x-cc3r)
- [GeoNetwork advisory GHSA-mh22-prqr-vf42 / CVE-2026-63219](https://github.com/geonetwork/core-geonetwork/security/advisories/GHSA-mh22-prqr-vf42)

For defensive use, upgrade to a fixed supported release and review reverse-proxy access to formatter upload endpoints.


