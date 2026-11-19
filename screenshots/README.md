# Screenshots

Evidence captured during the exercise, in order.

| File | Shows |
|---|---|
| 03-splunk-hydra-brute-events.png | The Hydra brute-force requests arriving in Splunk as `nginx:soc` events via HEC |
| 04-nmap-service-scan.png | Nmap service scan from Kali; ports 8081 and 8082 open on nginx 1.31.9 |
| 05-nikto-and-gobuster.png | Nikto findings and the Gobuster directory brute force results |
| 06-hydra-success.png | Hydra recovering `admin` / `password` on the DVWA brute-force page |
| 07-sqlmap-databases.png | sqlmap dumping the `dvwa` and `information_schema` databases |
| 07b-sqlmap-start.png | sqlmap confirming the `id` parameter is injectable (multiple techniques) |
| 07c-sqlmap-detail.png | sqlmap injection point detail and back-end DBMS fingerprint |
| 08-xss-and-juiceshop-attacks.png | Reflected XSS reflected back, Juice Shop login 401s, and the SQLi bypass returning the admin account |
| 09-attack-times-log.png | The attack-times log copied into the project |
| 10-detect-web-scanning.png | Detection 01: 404 flood, peak 7,401 not-found hits in a 5-minute window |
| 11-detect-attack-tools.png | Detection 02: Nmap, Gobuster, Hydra and sqlmap identified by user agent |
| 12-detect-sql-injection.png | Detection 03: SQL injection payloads in requested URLs |
| 13-detect-xss.png | Detection 04: XSS payloads in requested URLs |
| 14-detect-juiceshop-login-abuse.png | Detection 06: 13 login POSTs from the attacker (failures then the bypass) |
| 15-dashboard-web-soc-overview.png | The Web SOC Overview dashboard (requests over time, top IPs, attack tools, status codes) |
| 16-detection-files-created.png | The detection `.spl` files being written to the project |

Note: the environment-setup frames (containers healthy, HEC success curl) were
captured during the build but are not included here. The HEC success is also
implied by every Splunk capture, and the running stack is implied by every subsequent capture.

Redaction: the macOS menu bar, the local username and hostname in shell
prompts and file paths, and the DVWA session cookie have been blacked out.
