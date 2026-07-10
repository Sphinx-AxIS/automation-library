function Search-ZeekFeeds {
    <#
    .SYNOPSIS
        Searches optimized CriticalPathSecurity Zeek Intelligence Feeds for a specific IP address.

    .DESCRIPTION
        This function queries 24 IP-specific open-source threat intelligence feeds hosted in the 
        CriticalPathSecurity/Zeek-Intelligence-Feeds GitHub repository. It downloads the active lists 
        directly from GitHub's raw CDN to bypass API authentication/rate limits and checks for a 
        matching IP address (Indicator of Compromise).

    .PARAMETER TargetIP
        The single IPv4 address (e.g., "127.0.0.1") you wish to query against the intelligence feeds.

    .INPUTS
        System.String. You can pass an IP address as a string to the -TargetIP parameter.

    .OUTPUTS
        [PSCustomObject] containing the Feed name and the exact matching tab-delimited Intel line if found.

    .EXAMPLE
        Search-ZeekFeeds -TargetIP "<insert IPv4 here>"
        
        Description:
        Queries all 24 IP-specific feeds for the malicious IP. Returns matches from feeds like "compromised-ips.intel" and "sans.intel".

    .LINK
        https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds
    #>
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$TargetIP
    )

    # Escape the IP address dots for Regex matching
    $EscapedIP = [Regex]::Escape($TargetIP)

    $feeds = @(
        "abuse-ch-threatfox-ip.intel", "alienvault.intel", "atomspam.intel", 
        "avanzato_c2_ip.intel", "binarydefense.intel", "cloudzy.intel", 
        "cobaltstrike_ips.intel", "compromised-ips.intel", "cps-collected-iocs.intel", 
        "drb_ra_ip.intel", "drb_ra_ip_unverified.intel", "gru-aa25.intel", 
        "inversion.intel", "lockbit_ip.intel", "log4j_ip.intel", 
        "protonvpn.intel", "ragnar.intel", "rutgers.intel", "sans.intel", 
        "sip.intel", "stalkerware.intel", "stark-industries.intel", 
        "tor-exit.intel", "tweetfeed.intel"
    )

    Write-Host "Searching for $TargetIP across optimized Zeek feeds..." -ForegroundColor Cyan

    foreach ($feed in $feeds) {
        try {
            $uri = "https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/$feed"
            $data = Invoke-RestMethod -Uri $uri -ErrorAction Stop
            
            if ($data -match $EscapedIP) {
                $lines = $data -split "`n" | Select-String $EscapedIP
                foreach ($line in $lines) {
                    [PSCustomObject]@{
                        Feed  = $feed
                        Match = $line.Line.Trim()
                    }
                }
            }
        }
        catch {
            # Silently skip network/404 errors
        }
    }
}
