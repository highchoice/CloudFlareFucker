Try to find origin/real IP address behind cloudflare against possible IP range.
```
Usage:
usage: cloudflareFCK.py [-h] -d DOMAIN -iplist IPLIST [--proxy PROXY] [--threads THREADS] [--debug] [-v]
                        [--port PORT [PORT ...]]

Check a domain behind Cloudflare against a list of IPs.

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        The domain to check.
  -iplist IPLIST, --iplist IPLIST
                        File path to the list of IP addresses.
  --proxy PROXY         Optional proxy for requests (e.g., http://127.0.0.1:8080).
  --threads THREADS     Number of threads to use (default: 5).
  --debug               Prints request and response details for debugging.
  -v, --verbose         Enable verbose output for matched criteria.
  --port PORT [PORT ...]
                        Specify port(s) to test. If not provided, default ports 80 and 443 are used.
```

Useful info:
```
https://www.secjuice.com/finding-real-ips-of-origin-servers-behind-cloudflare-or-tor/
https://www.youtube.com/watch?v=UBZBL65Dv1w

Tools:
prips to generate ip list
```
