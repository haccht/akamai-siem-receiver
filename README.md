# akamai-siem-receiver

`akamai-siem-receiver` is a tool written in Go to collect SIEM logs from Akamai EdgeGrid API.


## Usage:

```
Usage:
  akamai-siem-receiver [OPTIONS]

Application Options:
  -c, --config=        WAF Config ID
      --offset=        Token that denotes the last message (default: NULL)
      --limit=         The approximate maximum number of security events each fetch returns (default: 10000)
  -f, --follow         Continue retrieving messages
  -i, --interval=      Interval of message retrieval (default: 5m)
      --format=        Output format (json or cef) (default: cef)
      --target=        Target URL for output over TCP/UDP (e.g., tcp://127.0.0.1:514)
  -r, --file=          Location of EdgeGrid file (default: ~/.edgerc)
  -s, --section=       Section of EdgeGrid file (default: default)
      --host=          EdgeGrid Host [$EDGEGRID_HOST]
      --client-token=  EdgeGrid ClientToken [$EDGEGRID_CLIENT_TOKEN]
      --client-secret= EdgeGrid ClientSecret [$EDGEGRID_CLIENT_SECRET]
      --access-token=  EdgeGrid AccessToken [$EDGEGRID_ACCESS_TOKEN]

Help Options:
  -h, --help           Show this help message
```

Run this tool with the WAF Config ID and you will get the Multi-JSON responses (use `--format json` to override the default CEF output).
Each event is listed on its own line, and the last line provides metadata on the whole batch.

```
$ akamai-siem-receiver --config 100000 --follow
{"attackData": {...}, "httpMessage": {...}, ...}
{"attackData": {...}, "httpMessage": {...}, ...}
{"attackData": {...}, "httpMessage": {...}, ...}
{"offset": "...", "total": 10000, "limit": 10000}
{"attackData": {...}, "httpMessage": {...}, ...}
{"attackData": {...}, "httpMessage": {...}, ...}
{"attackData": {...}, "httpMessage": {...}, ...}
{"offset": "...", "total": 10000, "limit": 10000}
```

When `--format cef` is used (the default), Akamai SIEM records are emitted as CEF while metadata lines (offset/total/limit) remain JSON and the `--follow` behavior is unchanged. Example:

```
$ akamai-siem-receiver --config 100000 --format cef
CEF:0|Akamai|SIEM Receiver|1.0|qik1_26545|SQL Injection Attack (SmartDetect)|10 src=192.0.2.82 dst=www.hmapi.com dpt=443 requestMethod=POST request=POST /?option=com_jce telnet.exe end=1491303422000 msg=Unknown Bots (HTTP Libraries); SQL Injection Attack (SmartDetect); SQL Injection Attack cs1Label=ruleMessages cs1=Unknown Bots (HTTP Libraries); SQL Injection Attack (SmartDetect); SQL Injection Attack cs2Label=ruleTags cs2=AKAMAI/BOT/UNKNOWN_BOT; ASE/WEB_ATTACK/SQLI; ASE/WEB_ATTACK/SQLI
```

To forward output directly to a collector over raw TCP/UDP sockets (without wrapping in RFC 3164/5424 syslog envelopes), provide `--target` (supported schemes: `tcp` and `udp`). When omitted, output is written to stdout. Metadata lines follow the selected format (CEF with JSON metadata or all JSON) and are sent to the same target:

```
$ akamai-siem-receiver --config 100000 --target tcp://127.0.0.1:514
```

CEF field mapping highlights:

- `attackData.clientIP` → `src`
- `httpMessage.host` → `dst`/`dhost`; `httpMessage.port` → `dpt`
- `httpMessage.method`/`path`/`query` → `requestMethod`/`request` (scheme inferred from TLS presence)
- `attackData.rules` → `cs1` (with `cs1Label=Rules`)
- `attackData.ruleMessages` → `msg` and `cs2` (with `cs2Label=Rule Messages`)
- `attackData.ruleData` → `cs3` (with `cs3Label=Rule Data`); `attackData.ruleSelectors` → `cs4` (with `cs4Label=Rule Selectors`)
- `userRiskData.risk` → `cs5` (with `cs5Label=Client Reputation`); `httpMessage.requestId` → `cs6` (with `cs6Label=API ID` and `devicePayloadId`)
- `attackData.configId` → `flexString1` (with `flexString1Label=Security Config Id`); `attackData.policyId` → `flexString2` (with `flexString2Label=Firewall Policy Id`)
- `httpMessage.bytes` → `out`
- `httpMessage.start` (Unix seconds) → `start` (Unix seconds)
- `attackData.ruleTags` → `AkamaiSiemRuleTags`; `attackData.ruleActions` → `AkamaiSiemRuleActions`
- `identity.ja4` (or `httpMessage.ja4`) → `AkamaiSiemJA4`; `identity.tlsFingerprintV2`/`identity.tlsFingerprintV3` (or legacy `httpMessage` fields) → `AkamaiSiemAKTLSFPv2`/`AkamaiSiemAKTLSFPv3`
- `httpMessage.tlsVersion` → `AkamaiSiemTLSVersion`
- request/response headers, geo fields, and response status are passed through with `AkamaiSiem*` prefixes
- Calculated fields per TechDocs: `attackData.appliedAction` drives `eventClassId` (`detect` for `alert`/`monitor`, else `mitigate`), which sets the CEF signature ID, `name` (`Activity detected` vs `Activity mitigated`), and `severity` (`5` vs `10`).


The events now arrive with URL-encoded, base64-encoded rule fields and identity fingerprints. Sample JSON line is as follows.

```
{
  "attackData": {
    "appliedAction": "alert",
    "clientIP": "192.0.2.82",
    "configId": "14227",
    "policyId": "qik1_26545",
    "ruleActions": "YWxlcnQ%3d%3bYWxlcnQ%3d%3bZGVueQ%3d%3d",
    "ruleData": "dGVsbmV0LmV4ZQ%3d%3d%3bdGVsbmV0LmV4ZQ%3d%3d%3bVmVjdG9yIFNjb3JlOiAxMCwgREVOWSB0aHJlc2hvbGQ6IDksIEFsZXJ0IFJ1bGVzOiA5NTAwMDI6OTUwMDA2LCBEZW55IFJ1bGU6ICwgTGFzdCBNYXRjaGVkIE1lc3NhZ2U6IFN5c3RlbSBDb21tYW5kIEluamVjdGlvbg%3d%3d",
    "ruleMessages": "U3lzdGVtIENvbW1hbmQgQWNjZXNz%3bU3lzdGVtIENvbW1hbmQgSW5qZWN0aW9u%3bQW5vbWFseSBTY29yZSBFeGNlZWRlZCBmb3IgQ29tbWFuZCBJbmplY3Rpb24%3d",
    "ruleSelectors": "QVJHUzpvcHRpb24%3d%3bQVJHUzpvcHRpb24%3d%3b",
    "ruleTags": "T1dBU1BfQ1JTL1dFQl9BVFRBQ0svRklMRV9JTkpFQ1RJT04%3d%3bT1dBU1BfQ1JTL1dFQl9BVFRBQ0svQ09NTUFORF9JTkpFQ1RJT04%3d%3bQUtBTUFJL1BPTElDWS9DTURfSU5KRUNUSU9OX0FOT01BTFk%3d",
    "ruleVersions": "NA%3d%3d%3bNA%3d%3d%3bMQ%3d%3d",
    "rules": "OTUwMDAy%3bOTUwMDA2%3bQ01ELUlOSkVDVElPTi1BTk9NQUxZ"
  },
  "botData": {
    "botScore": "100",
    "responseSegment": "3"
  },
  "clientData": {
    "appBundleId": "com.mydomain.myapp",
    "appVersion": "1.23",
    "sdkVersion": "4.7.1",
    "telemetryType": "2"
  },
  "format": "json",
  "geo": {
    "asn": "14618",
    "city": "ASHBURN",
    "continent": "288",
    "country": "US",
    "regionCode": "VA"
  },
  "httpMessage": {
    "bytes": "266",
    "host": "www.hmapi.com",
    "method": "GET",
    "path": "/",
    "port": "80",
    "protocol": "HTTP/1.1",
    "query": "option=com_jce%20telnet.exe",
    "requestHeaders": "User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml,application%2fxml%3bq%3d0.9,*%2f*%3bq%3d0.8%0d%0auniqueID%3a%20CR_H8%0d%0aAccept-Language%3a%20en-US,en%3bq%3d0.5%0d%0aAccept-Encoding%3a%20gzip,%20deflate%0d%0aConnection%3a%20keep-alive%0d%0aHost%3a%20www.hmapi.com%0d%0aContent-Length%3a%200%0d%0a",
    "requestId": "1158db1758e37bfe67b7c09",
    "responseHeaders": "Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml%0d%0aContent-Length%3a%20266%0d%0aExpires%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aDate%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aConnection%3a%20close%0d%0aSet-Cookie%3a%20ak_bmsc%3dAFE4B6D8CEEDBD286FB10F37AC7B256617DB580D417F0000FE7BE3580429E23D%7epluPrgNmaBdJqOLZFwxqQLSkGGMy4zGMNXrpRIc1Md4qtsDfgjLCojg1hs2HC8JqaaB97QwQRR3YS1ulk+6e9Dbto0YASJAM909Ujbo6Qfyh1XpG0MniBzVbPMUV8oKhBLLPVSNCp0xXMnH8iXGZUHlUsHqWONt3+EGSbWUU320h4GKiGCJkig5r+hc6V1pi3tt7u3LglG3DloEilchdo8D7iu4lrvvAEzyYQI8Hao8M0%3d%3b%20expires%3dTue,%2004%20Apr%202017%2012%3a57%3a02%20GMT%3b%20max-age%3d7200%3b%20path%3d%2f%3b%20domain%3d.hmapi.com%3b%20HttpOnly%0d%0a",
    "start": "1491303422",
    "status": "200"
  },
  "identity": {
    "ja4": "t13d201100_2b729b4bf6f3_9e7b989ebec8",
    "tlsFingerprintV2": "46008b1582967146",
    "tlsFingerprintV3": "3~fe38c35477967146"
  },
  "userRiskData": {
    "allow": "0",
    "emailDomain": "example.com",
    "general": "duc_1h:10|duc_1d:30",
    "originUserId": "jsmith007",
    "risk": "udfp:1325gdg4g4343g/M|unp:74256/H",
    "score": "75",
    "status": "0",
    "trust": "ugp:US",
    "username": "jsmith@example.com",
    "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
  },
  "version": "1.0"
}
```
