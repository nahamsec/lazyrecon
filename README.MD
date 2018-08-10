```
  _     ____  ____ ___  _ ____  _____ ____ ____  _
 / \   /  _ \/_   \\  \///  __\/  __//   _Y  _ \/ \  /|
 | |   | / \| /   / \  / |  \/||  \  |  / | / \|| |\ ||
 | |_/\| |-||/   /_ / /  |    /|  /_ |  \_| \_/|| | \||
 \____/\_/ \|\____//_/   \_/\_\\____\\____|____/\_/  \|

```

# Usage

`./lazyrecon.sh target.com`

# About

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

- Create a dated folder with recon notes
- Grab subdomains using Sublist3r and certspotter
- Grab a screenshot of responsive hosts 
- Grab the response header
- Perform nmap 
- Perform dirsearch 
- Generate a HTML report with output from the tools above
# Added features
- Resolve subdomains and export to txt file in hosts.txt
- Color coding in report.html for easier reading
- Added additional ports for nmap scan to detect azure cluster services
- Added check for dns records that points to azure/aws for possible subdmonain takeovers (manual check is required)

# More Features to be added
- Report suspicious redirects when doing content discovery 
- Massdns subdomain discovery
- Automate subdomain takeover detection on azure/aws

This requires [Bug Bounty Hunting Tools](https://github.com/nahamsec/bbht) in order for the tools to work. 

**Warning:** This code was originally created for personal use for myself, so it's  a bit messy and hopefully it'll be cleaned up with more features in a later release. 


