#!/bin/bash

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`


domain=

usage() { echo -e "Usage: $0 -d domain [-e]\n  Select -e to specify excluded domains\n " 1>&2; exit 1; }

while getopts "sd:" o; do
    case "${o}" in
        d)
            domain=${OPTARG}
            ;;

            #### working on subdomain exclusion
        e)
            excluded=${OPTARG}
            ;;

        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${domain}" ] ; then
   usage
fi

discovery(){
  hostalive $domain
  screenshot $domain
  cleanup $domain
  cat ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt | sort -u | while read line; do
    sleep 1
    subdomain=$(echo "$line" | awk '{print $1}')


#we pass subdomain with port number to dirsearcher so we can define the right arguments

    dirsearcher $line

#we pass domain value and subdomain without port number to report

    report $domain $subdomain
    echo "report generated for $line "
    sleep 1
  done

}


cleanup(){
  cd ./$domain/$foldername/screenshots/
  rename 's/_/-/g' -- *
  cd $path
}

hostalive(){

#read from the file alldomains and check if host is alive on port 80 and 443 and save results in two files responsive-date.txt and responsive-date-codes.txt
#the format of data in the file responsive-dates-codes.txt is as follows    test.example.com 443
#we need to store the ports so we can pass arguments correctly to dirsearch

  cat ./$domain/$foldername/alldomains.txt  | sort -u | while read line; do
        httpcl=$(curl --write-out %{http_code} --silent --output /dev/null -m 5 http://$line)
        httpssl=$(curl --write-out %{http_code} --silent --output /dev/null -m 5 -k https://$line)
    if [[ $httpcl = 000 && $httpssl = 000 ]]; then
      echo "$line was unreachable"
      echo "$line" >> ./$domain/$foldername/unreachable.txt
    elif [[ $httpcl = 000 && $httpssl != 000 ]]; then
      echo "$line is up on port 443"
      echo "$line 443" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt
      echo "$line" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
    else
      echo "$line is up on port 80"
      echo "$line 80" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt
      echo "$line" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
    fi
  done
}

screenshot(){
    echo "taking a screenshot of $line"
    python ~/tools/webscreenshot/webscreenshot.py -o ./$domain/$foldername/screenshots/ -i ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt --timeout=10 -m
}

recon(){

  echo "${green}Recon started on $domain ${reset}"
  echo "Listing subdomains using sublister..."
  python ~/tools/Sublist3r/sublist3r.py -d $domain -t 10 -v -o ./$domain/$foldername/$domain.txt > /dev/null
  echo "Checking certspotter..."
  curl -s https://certspotter.com/api/v0/certs\?domain\=$domain | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $domain >> ./$domain/$foldername/$domain.txt
  nsrecords $domain
  echo "Looking up ipaddress space..."
  asnlookup $domain
  echo "Starting discovery..."
  discovery $domain
  cat ./$domain/$foldername/$domain.txt | sort -u > ./$domain/$foldername/$domain.txt


}
asnlookup(){
#find ip address space of organization this is not bulletproof but it should work for now


 dm="$domain"
 org=$(echo "${dm%%.*}")
#get domain and remove .* example if we pass hackerone.com this will remove .com and the result would be hackerone
#we will use this to run asnlookup results will be stored to ipaddress.txt

 python ~/tools/asnlookup/asnlookup.py -o $org |  grep -E "*/[0-9]" > ./$domain/$foldername/ipaddress.txt

 if [[ -s "./$domain/$foldername/ipaddress.txt" ]]; then
    echo "${red}Ip address space found${reset}"
    cat ./$domain/$foldername/ipaddress.txt
    else
    echo "Could not find ip address space :/";
    fi

}

dirsearcher(){

#now that we have the subdomain with port 80/443 we can do simple check and then set urlscheme http or https
#note that if target is alive on both ports dirsearcher will default to port 80
#this is not bulletproof as it might overload the server because of concurrent connections on https  considering to implement other tools instead turbo intruder/ gobuster
  statcode=$(echo "$line" | awk '{print $2}')
  if [[ "$statcode" == "80" ]]; then
  urlscheme=http
  else
  urlscheme=https
  fi
  testdm=$(echo "$line" | awk '{print $1}')

  python3 ~/tools/dirsearch/dirsearch.py -e php,asp,aspx,jsp,html,zip,jar -u $urlscheme://$testdm
}

crtsh(){

# query crtsh and resolve results with massdns this is more convenient as it might reveal old dns records
# read reults from sulblist3r+certspotter and resolve using massdns again looking for old dns records

 ~/massdns/scripts/ct.py $domain | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/crtsh.txt
 cat ./$domain/$foldername/$domain.txt | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/domaintemp.txt
}

mass(){
# we run massdns with default settings we don't care about wildcard dns and bad resolvers we will clean up once the scan finishes
# download the latest Seclists collection https://github.com/danielmiessler/SecLists.git

 ~/massdns/scripts/subbrute.py ~/tools/SecLists/Discovery/DNS/jhaddix-dns.txt $domain | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S | grep -v 142.54.173.92 > ./$domain/$foldername/mass.txt
}
nsrecords(){

#this function will call crt.sh and massdns then it will look into results and remove any problems related to bad resolvers
#this function main obective is to find any azure , aws takeovers or any sort of old dns takeovers
                echo "Checking http://crt.sh"
                crtsh $domain > /dev/null
                echo "Starting Massdns Subdomain discovery this may take a while"
                mass $domain > /dev/null
                echo "Massdns finished..."
                echo "${green}Started dns records check...${reset}"
                echo "Looking into CNAME Records..."
#we will store all of the results from the previous tools to single temporary file

                cat ./$domain/$foldername/mass.txt >> ./$domain/$foldername/temp.txt
                cat ./$domain/$foldername/domaintemp.txt >> ./$domain/$foldername/temp.txt
                cat ./$domain/$foldername/crtsh.txt >> ./$domain/$foldername/temp.txt

#read the temporary file and detect wildcard dns remember we only need the first occurence of each domain
#save results to cleantemp.txt
                cat ./$domain/$foldername/temp.txt | awk '{print $3}' | sort -u | while read line; do
                wildcard=$(cat ./$domain/$foldername/temp.txt | grep -m 1 $line)
                echo "$wildcard" >> ./$domain/$foldername/cleantemp.txt
                done

#read the cleantemp grep for lines with CNAME then save it to a file

                cat ./$domain/$foldername/cleantemp.txt | grep CNAME >> ./$domain/$foldername/cnames.txt
                cat ./$domain/$foldername/cnames.txt | sort -u | while read line; do

#since the file output is as follows test.exmple.com. CNAME something.aws.com.
#we will take the first part run host and if the result is NXDOMAIN that means we just found an old dns record and possible takeover
#save results to pos.txt

                hostrec=$(echo "$line" | awk '{print $1}')
                if [[ $(host $hostrec | grep NXDOMAIN) != "" ]]
                then
                echo "${red}Check the following domain for NS takeover:  $line ${reset}"
                echo "$line" >> ./$domain/$foldername/pos.txt
                else
                echo -ne "working on it...\r"
                fi
                done
                sleep 1
                cat ./$domain/$foldername/$domain.txt > ./$domain/$foldername/alldomains.txt
                cat ./$domain/$foldername/cleantemp.txt | awk  '{print $1}' | while read line; do

#we take the first part of line test.exmple.com. CNAME something.aws.com. and remove the trailing dot

                x="$line"
                echo "${x%?}" >> ./$domain/$foldername/alldomains.txt
                done
                echo  "${green}Total of $(wc -l ./$domain/$foldername/alldomains.txt | awk '{print $1}') subdomains were found${reset}"
                sleep 1

        }

report(){

  touch ./$domain/$foldername/reports/$subdomain.html
  echo "<html>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<head>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<title>Recon Report for $subdomain</title>
<style>
.status.redirect{color:#d0b200}.status.fivehundred{color:#DD4A68}.status.jackpot{color:#0dee00}.status.weird{color:#cc00fc}img{padding:5px;width:360px}img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}pre{font-family:Inconsolata,monospace}pre{margin:0 0 20px}pre{overflow-x:auto}article,header,img{display:block}#wrapper:after,.blog-description:after,.clearfix:after{content:}.container{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2{margin-bottom:20px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}.container,table{width:100%}.site-header{overflow:auto}.post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}p{line-height:1.5em}pre,table td{padding:10px}h2{padding-top:40px;font-weight:900}a{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,"Helvetica Neue",Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}p{margin:0 0 30px}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}.row{display:flex}.column{flex:100%}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.post-header,.post-title,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.clearfix:after{display:table;clear:both}.container{max-width:100%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.site-header{padding:40px 0 0}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.post-title{font-size:55px;font-weight:900;margin:15px 0}.blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark{background-color:#1e2227;color:#fff}body.dark pre{background:#282c34}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}body.dark .status.redirect{color:#ecdb54}</style>
<script>
document.addEventListener('DOMContentLoaded', (event) => {
  ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
})
</script></head>" >> ./$domain/$foldername/reports/$subdomain.html
echo '<body class="dark"><header class="site-header">
<div class="site-title"><p>' >> ./$domain/$foldername/reports/$subdomain.html
echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>
</p>
</div>
</header>" >> ./$domain/$foldername/reports/$subdomain.html
echo '<div id="wrapper"><div id="container">'  >> ./$domain/$foldername/reports/$subdomain.html
echo "<h1 class=\"post-title\" itemprop=\"name headline\">Recon Report for <a href=\"http://$subdomain\">$subdomain</a></h1>" >> ./$domain/$foldername/reports/$subdomain.html
echo "<p class=\"blog-description\">Generated by LazyRecon on $(date) </p>" >> ./$domain/$foldername/reports/$subdomain.html
echo '<div class="container single-post-container">
<article class="post-container-left" itemscope="" itemtype="http://schema.org/BlogPosting">
<header class="post-header">
</header>
<div class="post-content clearfix" itemprop="articleBody">
<h2>Content Discovery</h2>' >> ./$domain/$foldername/reports/$subdomain.html

#read content discover results get the request response code then save to html with color coding

  echo "<pre>" >> ./$domain/$foldername/reports/$subdomain.html
  cat ~/tools/dirsearch/reports/$subdomain/* | while read nline; do
  status_code=$(echo "$nline" | awk '{print $1}')
  url=$(echo "$nline" | awk '{print $3}')
 if [[ "$status_code" == *20[012345678]* ]]; then
    echo "<a class='status jackpot' href='$url'>$nline</a>" >> ./$domain/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *30[012345678]* ]]; then
    echo "<a class='status redirect' href='$url'>$nline</a>" >> ./$domain/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *40[012345678]* ]]; then
    echo "<a href='$url'>$nline</a>" >> ./$domain/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *50[012345678]* ]]; then
    echo "<a class='status fivehundred' href='$url'>$nline</a>" >> ./$domain/$foldername/reports/$subdomain.html
  else
     echo "<a class='status weird' href='$url'>$nline</a>" >> ./$domain/$foldername/reports/$subdomain.html
  fi
done

  echo "</pre></div>" >> ./$domain/$foldername/reports/$subdomain.html

echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
<header class="post-header">
</header>
<div class="post-content clearfix" itemprop="articleBody">
<h2>Screenshots</h2>
<pre style="max-height: 340px;overflow-y: scroll">' >> ./$domain/$foldername/reports/$subdomain.html
echo '<div class="row">
  <div class="column">
Port 80' >> ./$domain/$foldername/reports/$subdomain.html
echo "<a href=\"../screenshots/http-$subdomain-80.png\"><img/src=\"../screenshots/http-$subdomain-80.png\"></a> " >> ./$domain/$foldername/reports/$subdomain.html
echo ' </div>
  <div class="column">
Port 443' >> ./$domain/$foldername/reports/$subdomain.html
  echo "<a href=\"../screenshots/https-$subdomain-443.png\"><img/src=\"../screenshots/https-$subdomain-443.png\"></a>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "</div></div></pre>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<h2>Dig Info</h2>
<pre>
$(dig $subdomain)
</pre>" >> ./$domain/$foldername/reports/$subdomain.html
echo "<h2>Host Info</h2>
<pre>
$(host $subdomain)
</pre>" >> ./$domain/$foldername/reports/$subdomain.html
echo "<h2>Response Headers</h2>
<pre>
$(curl -sSL -D - $subdomain  -o /dev/null)
</pre>" >> ./$domain/$foldername/reports/$subdomain.html
echo "<h2>NMAP Results</h2>
<pre>
$(nmap -sV -T3 -Pn -p2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $subdomain)
</pre>
</div></article></div>
</div></div></body></html>" >> ./$domain/$foldername/reports/$subdomain.html


}
master_report()
{

#this code will generate the html report for target it will have an overview of the scan
  echo '<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">' >> ./$domain/$foldername/master_report.html
echo "<title>Recon Report for $domain</title>
<style>.status.redirect{color:#d0b200}.status.fivehundred{color:#DD4A68}.status.jackpot{color:#0dee00}img{padding:5px;width:360px}img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}pre{font-family:Inconsolata,monospace}pre{margin:0 0 20px}pre{overflow-x:auto}article,header,img{display:block}#wrapper:after,.blog-description:after,.clearfix:after{content:}.container{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2{margin-bottom:20px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}.container,table{width:100%}.site-header{overflow:auto}.post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}p{line-height:1.5em}pre,table td{padding:10px}h2{padding-top:40px;font-weight:900}a{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,"Helvetica Neue",Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}p{margin:0 0 30px}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}.row{display:flex}.column{flex:100%}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.post-header,.post-title,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.clearfix:after{display:table;clear:both}.container{max-width:100%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.site-header{padding:40px 0 0}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.post-title{font-size:55px;font-weight:900;margin:15px 0}.blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark{background-color:#1e2227;color:#fff}body.dark pre{background:#282c34}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}body.dark .status.redirect{color:#ecdb54}</style>
<script>
document.addEventListener('DOMContentLoaded', (event) => {
  ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
})
</script></head>" >> ./$domain/$foldername/master_report.html




echo '<body class="dark"><header class="site-header">
<div class="site-title"><p>' >> ./$domain/$foldername/master_report.html
echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>
</p>
</div>
</header>" >> ./$domain/$foldername/master_report.html


 echo '<div id="wrapper"><div id="container">' >> ./$domain/$foldername/master_report.html
echo "<h1 class=\"post-title\" itemprop=\"name headline\">Recon Report for <a href=\"http://$domain\">$domain</a></h1>" >> ./$domain/$foldername/master_report.html
echo "<p class=\"blog-description\">Generated by LazyRecon on $(date) </p>" >> ./$domain/$foldername/master_report.html
echo '<div class="container single-post-container">
<article class="post-container-left" itemscope="" itemtype="http://schema.org/BlogPosting">
<header class="post-header">
</header>
<div class="post-content clearfix" itemprop="articleBody">
<h2>Total scanned subdomains</h2>
<table>
<tbody><tr>
 <th>Subdomains</th>
 <th>Scanned Urls</th>
 </tr>' >> ./$domain/$foldername/master_report.html

 #we just created the first part of the page now we just iterate through our scanned subdomains then we count number of found content from dirsearch directory
 #make sure you cleanup your dirsearch directory otherwise it will iterate throough all the files including your previous scans
 #all of this should be formatted inside a table

cat ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt | while read nline; do
echo "<tr>
 <td><a href='./reports/$nline.html'>$nline</a></td>
 <td>$(wc -l ~/tools/dirsearch/reports/$nline/* | awk '{print $1}')</td>
 </tr>" >> ./$domain/$foldername/master_report.html
done
echo "</tbody></table>
<div><h2>Possible NS Takeovers</h2></div>
<pre>" >> ./$domain/$foldername/master_report.html
cat ./$domain/$foldername/pos.txt >> ./$domain/$foldername/master_report.html
echo "</pre></div>" >> ./$domain/$foldername/master_report.html


echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
<header class="post-header">
</header>
<div class="post-content clearfix" itemprop="articleBody">
<h2>IP Address space</h2>
<pre>' >> ./$domain/$foldername/master_report.html
cat ./$domain/$foldername/ipaddress.txt >> ./$domain/$foldername/master_report.html
echo "</pre>
<h2>Dig Info</h2>
<pre>
$(dig $domain)
</pre>" >> ./$domain/$foldername/master_report.html
echo "<h2>Host Info</h2>
<pre>
$(host $domain)
</pre>" >> ./$domain/$foldername/master_report.html
echo "<h2>Response Headers</h2>
<pre>
$(curl -sSL -D - $domain  -o /dev/null)
</pre>" >> ./$domain/$foldername/master_report.html
echo "<h2>NMAP Results</h2>
<pre>
$(nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $domain)
</pre>
</div></article></div>
</div></div></body></html>" >> ./$domain/$foldername/master_report.html


}

logo(){
  #can't have a bash script without a cool logo :D
  echo "${red}
 _     ____  ____ ___  _ ____  _____ ____  ____  _
/ \   /  _ \/_   \\\  \///  __\/  __//   _\/  _ \/ \  /|
| |   | / \| /   / \  / |  \/||  \  |  /  | / \|| |\ ||
| |_/\| |-||/   /_ / /  |    /|  /_ |  \__| \_/|| | \||
\____/\_/ \|\____//_/   \_/\_\\\____\\\____/\____/\_/  \\|
${reset}                                                      "
}
cleantemp(){

    rm ./$domain/$foldername/temp.txt
    rm ./$domain/$foldername/domaintemp.txt
    rm ./$domain/$foldername/cleantemp.txt
    rm -rf ~/tools/dirsearch/reports/*.$domain
}
main(){
  clear
  logo
  if [ -d "./$domain" ]
  then
    echo "This is a known target."
  else
    mkdir ./$domain
  fi

  mkdir ./$domain/$foldername
  mkdir ./$domain/$foldername/reports/
  mkdir ./$domain/$foldername/screenshots/
  mkdir ./$domain/$foldername/content/
  touch ./$domain/$foldername/crtsh.txt
  touch ./$domain/$foldername/mass.txt
  touch ./$domain/$foldername/cnames.txt
  touch ./$domain/$foldername/pos.txt
  touch ./$domain/$foldername/alldomains.txt
  touch ./$domain/$foldername/temp.txt
  touch ./$domain/$foldername/domaintemp.txt
  touch ./$domain/$foldername/ipaddress.txt
  touch ./$domain/$foldername/cleantemp.txt
  touch ./$domain/$foldername/unreachable.html
  touch ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
  touch ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt
  touch ./$domain/$foldername/master_report.html
  rm -rf ~/tools/dirsearch/reports/*.$domain
  recon $domain
  master_report $domain
  echo "${green}Scan for $domain finished successfully${reset}"
  cleantemp $domain
}

path=$(pwd)
foldername=recon-$(date +"%Y-%m-%d")
main $domain
