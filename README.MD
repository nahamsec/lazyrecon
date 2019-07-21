```
  _     ____  ____ ___  _ ____  _____ ____ ____  _
 / \   /  _ \/_   \\  \///  __\/  __//   _Y  _ \/ \  /|
 | |   | / \| /   / \  / |  \/||  \  |  / | / \|| |\ ||
 | |_/\| |-||/   /_ / /  |    /|  /_ |  \_| \_/|| | \||
 \____/\_/ \|\____//_/   \_/\_\\____\\____|____/\_/  \|

```

# Usage

`./lazyrecon.sh -d target.com`
![Example Output](https://github.com/plenumlab/lazyrecon/blob/master/lazyrecon2.jpg)

# Lazyrecon updated

[+] Subdomain discovery using Sublist3r, certspotter, crt.sh and massdns

[+] Directory bruteforce with dirsearch

[+] 45 thousands dns query and more than 80 thousands http requests in less than 10 minutes

# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Create a dated folder with recon notes
- Grab subdomains using Sublist3r and certspotter
- Grab a screenshot of responsive hosts 
- Grab the response header
- Perform nmap 
- Perform dirsearch 
- Generate a HTML report with output from the tools above
- Color coding in report.html for easier reading
- Massdns subdomain discovery
- Massdns crt.sh subdomain discovery
- Find dead dns records 
- Notify for possible NS Subdomain takeover
- Improved reporting and less output while doing the work
- Find ip address space of target company

# New features
- Dirsearch is now MULTITHREADED (up to 10 subdomains scanned at a time)
- Grab data from wayback and parse Get parameters to be imported into intruder or other tools
- Grab javascript urls from wayback 
- Grab any php, jsp or aspx url from wayback



# Requirements
- Download the install script from https://github.com/nahamsec/bbht

# TO DO
# ADD CREDIT TO ORIGINAL DEVS



**Warning:** This code was originally created for personal use for myself, so it's  a bit messy and hopefully it'll be cleaned up with more features in a later release. 


