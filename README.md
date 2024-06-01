# CDNX
`cdnx` is a fast and simple tool to check if A record of a domain is within range of CDNs or not.

# Installation
```console
cargo install --git https://github.com/m333rl1n/cdnx.git
```

# Features
```console
$ cdnx -h
Usage: cdnx [OPTIONS] [PORTS]

Arguments:
  [PORTS]  Comma-sperated ports (e.g 80,443,8000)

Options:
  -t <THREAD>      Number of threads [default: 100]
  -a               Append CDN hosts
  -q               Do not print any message
  -h, --help       Print help
```

1. Simply remove CDN domains:
```console
$ printf "noneexists.zzz\nmedium.com\nford.com" | cdnx
ford.com
```
2. Only check if has A record or not (append CDN hosts to the resut):
```console
$ printf "noneexists.zzz\nmedium.com\nford.com" | cdnx -a
ford.com
medium.com
```
3. Set number of threads to use (default: 100):
```console
$ cat large.txt | cdnx -t 150
```
4. Combine with httpx (or any other tool) to prevent port scan on CDN hosts:
```console
$ printf "noneexists.zzz\nmedium.com\nford.com" | cdnx -a "80,443,8000,5000"
ford.com:80
ford.com:443
ford.com:8000
ford.com:5000
medium.com:80
medium.com:443

$ cat domains.txt | cdnx -a "80,443,8000,5000" | httpx
...
```
# Configurations
You cand your own ip range by editing `~/.config/cdnx/config.yaml`:
```yaml
Providers:
    - https://api.fastly.com/public-ip-list
    - https://www.cloudflare.com/ips-v4
    - https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips
    - https://support.maxcdn.com/hc/en-us/article_attachments/360051920551/maxcdn_ips.txt
    - https://cachefly.cachefly.net/ips/rproxy.txt
    - https://docs-be.imperva.com/api/bundle/z-kb-articles-km/page/c85245b7.html
    - http://edge.sotoon.ir/ip-list.json
    - https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json
    - https://raw.githubusercontent.com/m333rl1n/cdnx/main/static-CIDRs.txt
    - https://my.incapsula.com/api/integration/v1/ips

# default interval to update ip ranges is 2 day
Interval: 172800
```

# TODO
- [ ] Use custom DNS provider


