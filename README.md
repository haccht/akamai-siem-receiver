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
- `httpMessage.method`/`path`/`query` → `requestMethod`/`request`
- `attackData.rules` → `cs1` (with `cs1Label=Rules`)
- `attackData.ruleMessages` → `msg` and `cs2` (with `cs2Label=Rule Messages`)
- `attackData.ruleData` → `cs3` (with `cs3Label=Rule Data`); `attackData.ruleSelectors` → `cs4` (with `cs4Label=Rule Selectors`)
- `userRiskData.risk` → `cs5` (with `cs5Label=Client Reputation`); `httpMessage.requestId` → `cs6` (with `cs6Label=API ID` and `devicePayloadId`)
- `attackData.configId` → `flexString1` (with `flexString1Label=Security Config Id`); `attackData.policyId` → `flexString2` (with `flexString2Label=Firewall Policy Id`)
- `httpMessage.bytes` → `out`
- `httpMessage.start` (Unix seconds) → `start` (Unix seconds)
- `attackData.ruleTags` → `AkamaiSiemRuleTags`; request/response headers and geo fields are passed through with `AkamaiSiem*` prefixes
- Severity derives from `userRiskData.score` or `botData.botScore`


The events are all base64 decrypted. Sample JSON line is as follows.

```
{
  "attackData": {
    "clientIP": "192.0.2.82",
    "configId": "14227",
    "policyId": "qik1_26545",
    "ruleActions": ["monitor", "alert", "alert", "alert", "alert", "alert", "alert"],
    "ruleData": [
      "curl_6DF2908A3E7DB38917C8A52D98BCBE4F",
      "select * from users where userid",
      "select * from",
      "select * from users",
      "or 1=1",
      "3 SELECT Statement Keywords found within: select * from users where userid=1 or 1=1;",
      "Vector Score: 2015, Group Threshold: 9, Triggered Rules: 3000100-3000101-950007-950902-981300, Triggered Scores: 5-1000-5-1000-5, Triggered Selector: ARGS:q, Mitigated Rules: , Last Matched Message: "
    ],
    "ruleMessages": [
      "Unknown Bots (HTTP Libraries)",
      "SQL Injection Attack (SmartDetect)",
      "SQL Injection Attack",
      "SQL Injection Attack",
      "SQL Injection Attack (Tautology Probes 1)",
      "SQL Injection Attack",
      "Anomaly Score Exceeded for SQL Injection"
    ],
    "ruleSelectors": ["ARGS:q", "ARGS:q", "ARGS:q", "ARGS:q", "ARGS:q", "ARGS:q"],
    "ruleTags": [
      "AKAMAI/BOT/UNKNOWN_BOT",
      "ASE/WEB_ATTACK/SQLI",
      "ASE/WEB_ATTACK/SQLI",
      "ASE/WEB_ATTACK/SQLI",
      "ASE/WEB_ATTACK/SQLI",
      "ASE/WEB_ATTACK/SQLI",
      "ASE/WEB_ATTACK/SQLI"
    ],
    "ruleVersions": ["1", "9", "1", "1", "4", "4", "7"],
    "rules": ["3990001", "3000100", "3000101", "950007", "950902", "981300", "SQL-INJECTION-ANOMALY"]
  },
  "botData": {"botScore": "100", "responseSegment": "3"},
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
    "method": "POST",
    "path": "/",
    "port": "443",
    "protocol": "HTTP/1.1",
    "query": "option=com_jce%20telnet.exe",
    "requestHeaders": [
      "Host: www.hmapi.com",
      "User-Agent: curl/7.71.1-DEV",
      "Accept: */*",
      "Content-Length: 44",
      "Content-Type: application/x-www-form-urlencoded",
      "remove-dup-edge-ctrl-headers-rollout-enabled: 1"
    ],
    "responseHeaders": [
      "Content-Type: application/json; charset=utf-8",
      "Content-Length: 131",
      "Access-Control-Allow-Credentials: true",
      "Access-Control-Allow-Origin: *",
      "Expires: Tue, 20 Jul 2025 20:00:00 GMT",
      "Cache-Control: max-age=0, no-cache, no-store",
      "Date: Tue, 20 Jul 2025 20:00:00 GMT",
      "Connection: close",
      "Server-Timing: cdn-cache; desc=MISS",
      "Server-Timing: edge; dur=37",
      "Server-Timing: origin; dur=3",
      "X-Akamai-Staging: ESSL",
      "Server-Timing: ak_p; desc=\"1753227050862_389168420_27043222_4055_7076_13_19_15\";dur=1"
    ],
    "requestId": "1158db1758e37bfe67b7c09",
    "start": "1491303422",
    "status": "400"
  },
  "type": "akamai_siem",
  "userRiskData": {
    "allow": "0",
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
