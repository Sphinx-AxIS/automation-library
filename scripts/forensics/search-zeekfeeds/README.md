# Search-ZeekFeeds.psm1

`Search-ZeekFeeds.psm1` is a PowerShell module that rapidly queries an optimized list of 24 open-source IP threat intelligence feeds hosted in the CriticalPathSecurity Zeek repository. It is intended for quick Incident Response (IR) triage to determine if an IPv4 address is an active Indicator of Compromise (IOC).

## What it does

1. Connects directly to GitHub's raw Content Delivery Network (`raw.githubusercontent.com`) to bypass restrictive GitHub API rate limits and authentication requirements.
2. Iterates through 24 specific `.intel` files known to track malicious IP infrastructure (e.g., C2 nodes, compromised IPs, Tor exits, VPNs).
3. Safely sanitizes the target IP address for Regex searching.
4. Searches the feeds in memory and returns a structured object mapping the target IP to the exact feed and intelligence classification line where it was found.
5. Silently ignores 404/network errors so missing files do not pollute the console output during an active investigation.

## Basic usage

Because this is a PowerShell Module (`.psm1`) rather than a standard script, it must be imported into your session first.

```powershell
# 1. Import the module into memory
Import-Module .\Search-ZeekFeeds.psm1 -Force

# 2. Query a target IP
Search-ZeekFeeds -TargetIP "127.0.0.1"

# 3. Use pipeline input for multiple IPs
"127.0.0.1", "127.0.0.2" | Search-ZeekFeeds
