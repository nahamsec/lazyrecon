#!/bin/bash

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`
bgw=`tput setab 7`

urlscheme=http
port=80
domain=
curlflag=

usage() { echo -e "Usage: $0 -d domain [-s]\n  Select -s to use https to check host availability\n  Note that the SSL cert will not be validated" 1>&2; exit 1; }

while getopts "sd:" o; do
    case "${o}" in
        d)
            domain=${OPTARG}
            ;;
        s)
            urlscheme=https
            curlflag=-k
            port=443
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

echo "domain = ${domain}"
echo "scheme = ${urlscheme}"

discovery(){
  hostalive $domain
  screenshot $domain
  cleanup $domain
  cat ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt | sort -u | while read line; do
    sleep 1
    dirsearcher $line
    report $domain $line
    echo "$line report generated"
    sleep 1
  done

}

cleanup(){
  cd ./$domain/$foldername/screenshots/
  rename 's/_/-/g' -- *
  cd $path
}

hostalive(){

  cat ./$domain/$foldername/alldomains.txt  | sort -u | while read line; do
    if [ $(curl --write-out %{http_code} --silent --output /dev/null -m 5 $curlflag $urlscheme://$line) = 000 ]

    then
      echo "$line was unreachable"
      touch ./$domain/$foldername/unreachable.html
      echo "<b>$line</b> was unreachable<br>" >> ./$domain/$foldername/unreachable.html
    else
      echo "$line is up"
      echo $line >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
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
  echo "Starting discovery..."
  discovery $domain
  cat ./$domain/$foldername/$domain.txt | sort -u > ./$domain/$foldername/$domain.txt


}

dirsearcher(){
  python3 ~/tools/dirsearch/dirsearch.py -e php,asp,aspx,jsp,html,zip,jar -u $line
}
crtsh(){
 ~/massdns/scripts/ct.py $domain | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/crtsh.txt
}
mass(){
 ~/massdns/scripts/subbrute.py ./all.txt $domain | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S | grep -v 142.54.173.92 > ./$domain/$foldername/mass.txt
}
nsrecords(){
                echo "${green}Started dns records check...${reset}"
                echo "Checking http://crt.sh"
                crtsh $domain > /dev/null
                echo "Starting Massdns Subdomain discovery this may take a while"
                mass $domain > /dev/null
                echo "Massdns finished..."
                echo "Looking into CNAME Records..."
                cat ./$domain/$foldername/mass.txt >> ./$domain/$foldername/temp.txt
                cat ./$domain/$foldername/crtsh.txt >> ./$domain/$foldername/temp.txt
                cat ./$domain/$foldername/temp.txt | awk '{print $3}' | sort -u | while read line; do
                wildcard=$(cat ./$domain/$foldername/temp.txt | grep -m 1 $line)
                echo "$wildcard" >> ./$domain/$foldername/cleantemp.txt
                done
                cat ./$domain/$foldername/cleantemp.txt | grep CNAME >> ./$domain/$foldername/cnames.txt
                cat ./$domain/$foldername/cnames.txt | sort -u | while read line; do
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
                x="$line"
                echo "${x%?}" >> ./$domain/$foldername/alldomains.txt
                done
                echo  "${green}Total of $(wc -l ./$domain/$foldername/alldomains.txt | awk '{print $1}') subdomains were found${reset}"
                sleep 1

        }

report(){

  touch ./$domain/$foldername/reports/$line.html
  echo "<title> report for $line </title>" >> ./$domain/$foldername/reports/$line.html
  echo "<html>" >> ./$domain/$foldername/reports/$line.html
  echo "<head>" >> ./$domain/$foldername/reports/$line.html
  echo "<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css?family=Mina\" rel=\"stylesheet\">" >> ./$domain/$foldername/reports/$line.html
  echo "</head>" >> ./$domain/$foldername/reports/$line.html
  echo "<body><meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\"> <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js\"></script> <script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js\"></script></body>" >> ./$domain/$foldername/reports/$line.html
  echo "<div class=\"jumbotron text-center\"><h1> Recon Report for <a/href=\"http://$line.com\">$line</a></h1>" >> ./$domain/$foldername/reports/$line.html
  echo "<p> Generated by <a/href=\"https://github.com/nahamsec/lazyrecon\"> LazyRecon</a> on $(date) </p></div>" >> ./$domain/$foldername/reports/$line.html


  echo "<div clsas=\"row\">" >> ./$domain/$foldername/reports/$line.html
  echo "<div class=\"col-sm-6\">" >> ./$domain/$foldername/reports/$line.html
  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Dirsearch</h2></div>" >> ./$domain/$foldername/reports/$line.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$line.html
  cat ~/tools/dirsearch/reports/$line/* | while read nline; do
  status_code=$(echo "$nline" | awk '{print $1}')
  url=$(echo "$nline" | awk '{print $3}')
  if [[ "$status_code" == *20[012345678]* ]]; then
    echo "<span style='background-color:#00f93645;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$line.html
  elif [[ "$status_code" == *30[012345678]* ]]; then
    echo "<span style='background-color:#f9f10045;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$line.html
  elif [[ "$status_code" == *40[012345678]* ]]; then
    echo "<span style='background-color:#0000cc52;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$line.html
  elif [[ "$status_code" == *50[012345678]* ]]; then
    echo "<span style='background-color:#f9000045;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$line.html
  else
    echo "<span>$line</span>" >> ./$domain/$foldername/reports/$line.html
  fi
done

  echo "</pre>   </div>" >> ./$domain/$foldername/reports/$line.html


  echo "<div class=\"col-sm-6\">" >> ./$domain/$foldername/reports/$line.html
  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Screeshot</h2></div>" >> ./$domain/$foldername/reports/$line.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$line.html
  echo "Port 80                              Port 443" >> ./$domain/$foldername/reports/$line.html
  echo "<img/src=\"../screenshots/http-$line-80.png\" style=\"max-width: 500px;\"> <img/src=\"../screenshots/https-$line-443.png\" style=\"max-width: 500px;\"> <br>" >> ./$domain/$foldername/reports/$line.html
  echo "</pre>" >> ./$domain/$foldername/reports/$line.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Dig Info</h2></div>" >> ./$domain/$foldername/reports/$line.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$line.html
  dig $line >> ./$domain/$foldername/reports/$line.html
  echo "</pre>" >> ./$domain/$foldername/reports/$line.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Host Info</h1></div>" >> ./$domain/$foldername/reports/$line.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$line.html
  host $line >> ./$domain/$foldername/reports/$line.html
  echo "</pre>" >> ./$domain/$foldername/reports/$line.html


  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Response Header</h1></div>" >> ./$domain/$foldername/reports/$line.html
  echo "<pre>" >> ./$domain/$foldername/reports/$line.html
  curl -sSL -D - $line  -o /dev/null >> ./$domain/$foldername/reports/$line.html
  echo "</pre>" >> ./$domain/$foldername/reports/$line.html


  echo "<div style=\"font-family: 'Mina', serif;\"><h1>Nmap Results</h1></div>" >> ./$domain/$foldername/reports/$line.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$line.html
  echo "nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080" >> ./$domain/$foldername/reports/$line.html
  nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $line >> ./$domain/$foldername/reports/$line.html
  echo "</pre>">> ./$domain/$foldername/reports/$line.html



  echo "</html>" >> ./$domain/$foldername/reports/$line.html

}
master_report()
{
  echo "<title> Master report for $domain </title>" >> ./$domain/$foldername/master_report.html
  echo "<html>" >> ./$domain/$foldername/master_report.html
  echo "<head>" >> ./$domain/$foldername/master_report.html
  echo "<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css?family=Mina\" rel=\"stylesheet\">" >> ./$domain/$foldername/master_report.html
  echo "</head>" >> ./$domain/$foldername/master_report.html
  echo "<body><meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\"> <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js\"></script> <script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js\"></script></body>" >> ./$domain/$foldername/master_report.html
  echo "<div class=\"jumbotron text-center\"><h1> Recon Report for <a/href=\"http://$domain\">$domain</a></h1>" >> ./$domain/$foldername/master_report.html
  echo "<p> Generated by <a/href=\"https://github.com/nahamsec/lazyrecon\"> LazyRecon</a> on $(date) </p></div>" >> ./$domain/$foldername/master_report.html


  echo "<div class=\"col-sm-6\">" >> ./$domain/$foldername/master_report.html
  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Total scanned subdomains</h2></div>" >> ./$domain/$foldername/master_report.html

  echo "<pre style='display: block;'>" >> ./$domain/$foldername/master_report.html
  echo "<div class=\"col-sm-6\">" >> ./$domain/$foldername/master_report.html
  echo "SubDomains" >> ./$domain/$foldername/master_report.html

  cat ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt | while read nline; do
  echo "<span><a href='./reports/$nline.html'>$nline</a></span>" >> ./$domain/$foldername/master_report.html
  done
  echo "</div>" >> ./$domain/$foldername/master_report.html
  echo "<div class=\"col-sm-6\">Scanned Urls" >> ./$domain/$foldername/master_report.html

  cat ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt | while read nline; do
  echo "<span>$(wc -l ~/tools/dirsearch/reports/$nline/* | awk '{print $1}')</span>" >> ./$domain/$foldername/master_report.html
  done
  echo "</div>" >> ./$domain/$foldername/master_report.html
  echo "</pre>" >> ./$domain/$foldername/master_report.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Possible NS Takeovers</h2></div>" >> ./$domain/$foldername/master_report.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/master_report.html
  cat ./$domain/$foldername/pos.txt | while read ns; do
  echo "<span>$ns</span>" >> ./$domain/$foldername/master_report.html
  done
  echo "</pre></div>" >> ./$domain/$foldername/master_report.html

  echo "<div class=\"col-sm-6\">" >> ./$domain/$foldername/master_report.html
  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Dig Info</h2></div>" >> ./$domain/$foldername/master_report.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/master_report.html
  dig $line >> ./$domain/$foldername/master_report.html
  echo "</pre>" >> ./$domain/$foldername/master_report.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Host Info</h1></div>" >> ./$domain/$foldername/master_report.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/master_report.html
  host $domain >> ./$domain/$foldername/master_report.html
  echo "</pre>" >> ./$domain/$foldername/master_report.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Response Header</h1></div>" >> ./$domain/$foldername/master_report.html
  echo "<pre>" >> ./$domain/$foldername/master_report.html
  curl -sSL -D - $domain  -o /dev/null >> ./$domain/$foldername/master_report.html
  echo "</pre>" >> ./$domain/$foldername/master_report.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h1>Nmap Results</h1></div>" >> ./$domain/$foldername/master_report.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/master_report.html
  echo "nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080" >> ./$domain/$foldername/master_report.html
  nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $domain >> ./$domain/$foldername/master_report.html
  echo "</pre>">> ./$domain/$foldername/master_report.html

  echo "</div>" >> ./$domain/$foldername/master_report.html


  echo "</html>" >> ./$domain/$foldername/master_report.html

  echo "${green}Scan for $domain finished successfully${reset}"
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
  touch ./$domain/$foldername/crtsh.txt
  touch ./$domain/$foldername/mass.txt
  touch ./$domain/$foldername/cnames.txt
  touch ./$domain/$foldername/pos.txt
  touch ./$domain/$foldername/alldomains.txt
  touch ./$domain/$foldername/temp.txt
  touch ./$domain/$foldername/cleantemp.txt
  touch ./$domain/$foldername/unreachable.html
  touch ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
  touch ./$domain/$foldername/master_report.html
  rm -rf ~/tools/dirsearch/reports/*.$domain
  recon $domain
  master_report $domain
  rm ./$domain/$foldername/temp.txt
  rm ./$domain/$foldername/cleantemp.txt





}
logo

path=$(pwd)
foldername=recon-$(date +"%Y-%m-%d")
main $domain
