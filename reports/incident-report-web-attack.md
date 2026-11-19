# Incident Report: Web Application Attack Against DVWA and Juice Shop

**Analyst:** Marvin Castro Hernandez
**Date of report:** 2026-11-19
**Environment:** Containerized SOC lab (Splunk Enterprise, nginx reverse proxy, DVWA, OWASP Juice Shop, Kali)
**Severity:** High
**Status:** Detected; containment recommended (see Section 5)

## 1. Summary

A single internal source, 192.168.107.2 (the Kali attacker container), carried out a full web attack sequence against two applications behind the monitored nginx reverse proxy. The activity moved from reconnaissance (Nmap, Nikto, Gobuster) into credential attacks (Hydra against DVWA, password spraying against Juice Shop) and then exploitation (sqlmap confirming SQL injection in DVWA, a reflected XSS probe, and a SQL injection login bypass in Juice Shop). All eight actions were detected in Splunk from nginx access logs shipped over the HTTP Event Collector (HEC). The source accounted for roughly 94% of all web traffic in the window. The recommended first containment step is to block it at the proxy (Section 5).

## 2. Timeline

All times are America/New_York, as displayed in Splunk. The lab clock inside the Kali container records UTC, so the raw `attack-times.txt` values are five hours ahead of the times below.

| Time (ET) | Event | Evidence | MITRE ATT&CK |
|---|---|---|---|
| 18:33 | Nmap service scan of ports 8081 and 8082 | user agent `Nmap Scripting Engine`, 8 to 16 requests | T1595.001 Active Scanning: Scanning IP Blocks |
| ~18:34 to 18:37 | Nikto vulnerability scan of DVWA (7,794 requests) | 404 flood, plus speculative SQLi and XSS probe payloads | T1595.002 Vulnerability Scanning |
| 19:31 | Gobuster directory brute force of DVWA | user agent `gobuster/3.8.2`, 4,615 requests | T1595.003 Wordlist Scanning |
| 19:34 | Hydra password guessing on the DVWA brute-force page | user agent `Mozilla/5.0 (Hydra)`, 40 requests; found `admin` / `password` | T1110.001 Password Guessing |
| 19:36 | sqlmap SQL injection against the DVWA `id` parameter | user agent `sqlmap/1.10.10`, 193 requests; dumped database names | T1190 Exploit Public-Facing Application |
| 19:48 | Reflected XSS probe against DVWA `xss_r` | `<script>alert(1)</script>` reflected back | T1059.007 JavaScript / T1190 |
| 19:48 to 19:49 | Juice Shop admin login password guessing | 12 POST `/rest/user/login`, all HTTP 401 | T1110.001 Password Guessing |
| 19:49 | Juice Shop SQL injection login bypass | `' OR 1=1--` in the login body returned the admin session | T1190 Exploit Public-Facing Application |

## 3. Detection

Each row maps to a saved SPL detection in the `detections/` folder. Result counts are from the Splunk runs captured during the exercise.

| Detection | File | What it caught | Result |
|---|---|---|---|
| Web scanning (404 flood) | 01-web-scanning.spl | More than 50 HTTP 404s from one IP in a 5-minute window | 3 windows flagged; peak 7,401 not-found hits (7,160 unique paths) in one 5-minute bin, all from 192.168.107.2 against DVWA |
| Attack-tool user agents | 02-attack-tool-user-agents.spl | Known scanner and tool names in the user agent | 4 tools from 192.168.107.2: gobuster (4,615), sqlmap (193), Hydra (40), Nmap (8, rising to 16) |
| SQL injection in URL | 03-sql-injection.spl | SQL syntax in requested URLs | 27 matching requests (sqlmap UNION and information_schema payloads, plus Nikto SQLi probes) |
| Cross-site scripting in URL | 04-xss.spl | Script tags and JS handlers in requested URLs | 640 matching requests (mostly Nikto probe payloads across many paths) |
| DVWA password guessing | 05-dvwa-password-guessing.spl | Repeated hits on the DVWA brute-force page | Corroborated by the 40 Hydra requests in detection 02; Hydra recovered `admin` / `password` |
| Juice Shop login abuse | 06-juiceshop-login-abuse.spl | Many failed logins followed by a success from one IP | 13 POST `/rest/user/login` events from 192.168.107.2 (12 failures, then the injection bypass) |

Dashboard (`Web SOC Overview`) corroboration:
- Top Source IPs: 192.168.107.2 generated 20,497 requests (94.3% of all traffic); 192.168.107.1, the Docker gateway and health-check traffic, made up the remaining 5.7%.
- Status Codes: the request mix was dominated by HTTP 404, consistent with heavy scanning.
- Attack Tools Seen: Nmap, Gobuster, Hydra and sqlmap all appeared by user agent with first-seen and last-seen timestamps.

## 4. Analysis

- All malicious activity came from one source and followed a textbook kill chain: reconnaissance, then credential access, then exploitation. The volume (over 20,000 requests, 94% of the window) made the source trivial to pick out by request count alone.
- Most of the SQL injection and XSS detection volume came from Nikto's speculative probe payloads rather than from the dedicated exploitation tools. That is a useful triage lesson: the signature-style detections (03 and 04) fire on any payload that looks like an attack, so an analyst still has to separate a scanner throwing thousands of guesses from a tool like sqlmap that confirmed a real, exploitable injection. The sqlmap run is the one that actually enumerated the `dvwa` and `information_schema` databases.
- The Juice Shop SQL injection login bypass lived in the POST request body, which nginx access logs do not record. The URL-based SQLi detection (03) could not see that payload. It was caught behaviorally instead, by detection 06, which keys on a burst of failed logins followed by a success from the same source. Knowing where your logs are blind is as important as writing the detections.
- The attack tools announced themselves in the user agent (Nmap, gobuster, Hydra, sqlmap), which made detection 02 easy. A real adversary would spoof or randomize the user agent, so user-agent rules are a convenience, not a control. The behavior-based detections (404 flood rate, failed-then-success login pattern) are the ones that would survive an attacker who cleans up their user agent.
- Impact in the lab: DVWA admin credentials recovered, DVWA database names exposed through SQL injection, a reflected XSS vector confirmed, and the Juice Shop admin account accessed without the password.

## 5. Response

The actions below are recommended. They were planned as part of the lab but not carried out during this exercise.

- **Containment (recommended):** Block 192.168.107.2 at the nginx reverse proxy by adding `deny 192.168.107.2;` to a file in `nginx/blocklist/` and reloading nginx (`nginx -s reload`, no downtime). Verify the block by confirming HTTP 403 responses for that source in Splunk with detection 07 (`07-blocked-requests.spl`). Blocking at the proxy is the fastest option because every request to both applications already passes through it.
- **Eradication (recommended):** Reset the DVWA and Juice Shop admin credentials. Remediate the injection flaws with parameterized queries and the XSS with output encoding. In a real environment, hunt for any persistence or data staged during the window the source had access.
- **Recovery (recommended):** Restore affected application data from a known-good backup and keep these six detections running for a follow-up watch period to catch repeat activity from the same source or user agents.

## 6. Lessons Learned

1. Put a web application firewall (such as ModSecurity) in front of the applications so obvious scanner and injection traffic is blocked before it reaches the app.
2. Rate-limit and lock out login endpoints so credential guessing cannot run 40-plus attempts unimpeded.
3. Log request bodies on sensitive endpoints (or add app-level logging) so POST-body attacks like the Juice Shop bypass are visible to analysts, not just the behavioral signal.
4. Pair user-agent detections with behavior-based ones, since user agents are trivial for an attacker to change.

## 7. Evidence

Screenshots referenced by this report are in the `screenshots/` folder (see `screenshots/README.md` for the file list). The SPL for every detection is in the `detections/` folder.
