# Attack Timeline (raw)

Captured from the Kali container's `attack-times.txt`. The container clock is UTC;
subtract 5 hours for America/New_York (the Splunk display timezone).

| # | Attack | Time (UTC) | Time (ET) |
|---|---|---|---|
| 1 | Nmap service scan | Nov 18 23:33:19 | Nov 18 18:33 |
| 2 | Nikto vulnerability scan | Nov 18 23:34:27 | Nov 18 18:34 |
| 3 | Gobuster directory brute force | Nov 19 00:31:46 | Nov 18 19:31 |
| 4 | Hydra password guessing | Nov 19 00:34:34 | Nov 18 19:34 |
| 5 | sqlmap SQL injection | Nov 19 00:36:27 | Nov 18 19:36 |
| 6 | Reflected XSS test | Nov 19 00:48:31 | Nov 18 19:48 |
| 7 | Juice Shop login guessing | Nov 19 00:48:51 | Nov 18 19:48 |
| 8 | Juice Shop SQL injection login bypass | Nov 19 00:49:11 | Nov 18 19:49 |

Attacker source IP (as seen in the proxy logs): 192.168.107.2
Proxy container: 192.168.107.3   Docker gateway / health checks: 192.168.107.1
