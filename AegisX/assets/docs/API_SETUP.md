# AegisX — API Setup Guide

AegisX v1 ships with **nine intelligence provider adapters** — three of them
**keyless community sources that work the moment the app starts** (zero
configuration, zero keys, zero accounts):

| Keyless (zero setup) | What it gives you |
| --- | --- |
| **Community DNS Intel** | Spamhaus DBL/ZEN blocklist reputation, Tor exit-node detection, reverse DNS |
| **DNS over HTTPS** | live A/NS/MX/TXT resolution (Google DoH) + sub-domain discovery from crt.sh CT logs |
| **OpenGeo Web** | keyless IP geolocation (ipwho.is → ip-api.com fallback): country, city, ASN, organization |

> **Out of the box:** install → launch → search any IP/domain and you already
> get **live, real-world intelligence** through the keyless sources above.
> A key only adds extra commercial feeds on top. Until one key-based provider
> is configured (optional), indicators that are never queried live still work
> through the labelled demonstration corpus.

## Provider overview

| Provider | Key required | Capabilities | Rate limit used | Cache TTL |
| --- | :---: | --- | --- | --- |
| **Community DNS Intel** | No | Spamhaus DBL/ZEN, Tor exit detection, reverse DNS | 1.5 s interval | 12 h |
| **DNS over HTTPS** | No | DNS records (A/NS/MX/TXT), CT-log sub-domains | 1 s interval | 6 h |
| **OpenGeo Web** | No | IP geo/city/ASN/org, map enrichment | 1.5 s interval | 14 d |
| **AbuseIPDB** | Yes | IP abuse confidence, report counts, ISP/usage | 1.2 s interval | 6 h |
| **AlienVault OTX** | Yes | pulse memberships, tags, adversary mentions, geo/ASN | 1.2 s interval | 6 h |
| **VirusTotal** | Yes | multi-engine verdicts, detections, categories | 2.5 s interval | 6 h |
| **URLhaus** (abuse.ch) | Free Auth-Key | malicious URLs, payload signatures, malware delivery | 2 s interval | 2 h |
| **ThreatFox** (abuse.ch) | Free Auth-Key | IOC search with malware family + confidence | 2 s interval | 2 h |
| **MaxMind GeoIP** | Local DB | high-precision city/country geolocation for IPs | local | 30 d |

> **abuse.ch change (2025):** URLhaus and ThreatFox now require a free
> `Auth-Key` for every data query. Get one at the abuse.ch authentication
> portal (<https://auth.abuse.ch/>) — one key covers both. Without it the
> app runs **fully zero-config** on the keyless community feeds, the
> abuse.ch cards show a friendly `FREE KEY OPTIONAL` badge, and their
> connectivity probes still report `ONLINE` (the keyless POST proves the
> API is reachable — never a red error). Paste the key in Configure and
> the full IOC / malware-URL queries come alive.

## Obtaining keys (all free tiers)

### AbuseIPDB
1. Create an account at <https://www.abuseipdb.com/register>.
2. Go to **Account → API** (<https://www.abuseipdb.com/account/api>).
3. Create a new API key and copy it.
4. Free tier: 1,000 checks/day.

### AlienVault OTX
1. Register at <https://otx.alienvault.com>.
2. Open **Settings → API** (<https://otx.alienvault.com/settings/api>).
3. Copy your OTX key.

### VirusTotal
1. Create an account at <https://www.virustotal.com>.
2. Copy the key from your profile API page.
3. Free tier: 4 requests/min (AegisX enforces a 2.5 s interval).

### URLhaus + ThreatFox (one shared free Auth-Key)
1. Create a free account at the abuse.ch authentication portal:
   <https://auth.abuse.ch/>.
2. Copy the Auth-Key.
3. Paste it in both the URLhaus and ThreatFox Configure dialogs (same key).
4. Requests automatically carry the `Auth-Key` header from that moment on.

### MaxMind GeoIP (local database)
1. Create a free MaxMind account (<https://www.maxmind.com/en/geolite2/signup>).
2. Download **GeoLite2-City** in MMDB format.
3. In AegisX: **Settings → Intelligence Sources → MaxMind GeoIP → Configure**
   and set the `.mmdb` file path.
4. Optional but recommended: `pip install geoip2` inside the app environment.
   (Until configured, the keyless **OpenGeo Web** source already provides
   country/ASN enrichment for maps.)

## Entering keys in AegisX

**Settings → Intelligence Sources → [Provider] → Configure**

- The dialog shows a clickable **Get a free key** link for every key-based
  provider.
- Paste the key, click **Test connection** (a real, cheap API call), then
  **Save**.
- Status chips update automatically: `NOT CONFIGURED → READY → ONLINE`.
- **Remove key** disables the provider again.

## Where keys are stored

| Backend | Location | Notes |
| --- | --- | --- |
| System keyring (preferred) | your desktop keyring | strongest protection; install `keyring` in the app venv |
| Fallback file | `~/.config/aegisx/keys.json` | stream-cipher sealed with a machine-id-derived key, `chmod 600` |

Keys never leave your machine and are transmitted only over HTTPS to the
specific provider you are querying. The Settings page always shows which
backend is active.

## Environment-variable alternative

For automation you can provide keys via `~/.config/aegisx/aegisx.env`
(see `config.example.env`):

```
AEGISX_ABUSEIPDB_KEY=...
AEGISX_OTX_KEY=...
AEGISX_VIRUSTOTAL_KEY=
AEGISX_GEOIP_DB=/path/GeoLite2-City.mmdb
```

Environment values take precedence over stored settings.

## Honest data policy

The keyless sources query real infrastructure (Spamhaus DNS zones, Tor
project exit list, Google DoH, crt.sh, ipwho.is) exactly like the commercial
feeds query their APIs. Demonstration-mode records are always labelled
`[SAMPLE DATA]` so sample and live intelligence can never be confused.
