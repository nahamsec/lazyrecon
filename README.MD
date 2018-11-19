```
  _     ____  ____ ___  _ ____  _____ ____ ____  _
 / \   /  _ \/_   \\  \///  __\/  __//   _Y  _ \/ \  /|
 | |   | / \| /   / \  / |  \/||  \  |  / | / \|| |\ ||
 | |_/\| |-||/   /_ / /  |    /|  /_ |  \_| \_/|| | \||
 \____/\_/ \|\____//_/   \_/\_\\____\\____|____/\_/  \|

```

# Usage

`./lazyrecon.sh target.com`
![Example Output](https://github.com/plenumlab/lazyrecon/blob/master/Lazyrecon1.jpg)

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
# Added features
- Massdns subdomain discovery
- Massdns crt.sh subdomain discovery
- Find dead dns records 
- Notify for possible NS Subdomain takeover
- Improved reporting and less output while doing the work

# Requirements
This requires [Bug Bounty Hunting Tools](https://github.com/nahamsec/bbht) in order for the tools to work. 

This requires Massdns installed in the root directory https://github.com/blechschmidt/massdns.

Make sure you download all.txt file its a huge wordlist used by massdns.



**Warning:** This code was originally created for personal use for myself, so it's  a bit messy and hopefully it'll be cleaned up with more features in a later release. 


