#!/bin/bash

# set variables
url=$1
scope=$2
ppath=~/projects
scope_path=$ppath/$scope/recon/$url

timestamp=$(date +%s)
scan_path=$scope_path/$url-$timestamp

if [[ ! -d $scan_path ]]
then
    echo "Path Does Not Exist!"
    mkdir -p $scan_path
fi

cd $scan_path

subs_path=$scan_path/subs
hosts_path=$scan_path/hosts
portscan_path=$scan_path/ports
tech_path=$scan_path/tech
takeover_path=$scan_path/takeovers
content_path=$scan_path/content
quick_wins=$content_path/quick_wins

if [[ ! -d $subs_path ]];
then
    mkdir $subs_path
fi

if [[ ! -d $hosts_path ]];
then
    mkdir $hosts_path
fi

if [[ ! -d $portscan_path ]];
then
    mkdir $portscan_path
fi

if [[ ! -d $tech_path ]];
then
    mkdir $tech_path
fi

if [[ ! -d $takeover_path ]];
then
    mkdir $takeover_path
fi

if [[ ! -d $content_path ]];
then
    mkdir $content_path
fi

if [[ ! -d $quick_wins ]];
then
    mkdir $quick_wins
fi

### Perform Scan ###
echo "Starting scan for Company: $scope on Url: $url"
echo "Stored in $scope_path"
sleep 3


### Perform Subdomain Enumeration

echo "Beginning subdomain enumeration on $url"

echo '--------------------------------------------'
echo '--------------------------------------------'

# Subfinder Scan
echo 'subfinder scan'
subfinder -d $url -all -cs -o $subs_path/domains.txt
cat $subs_path/domains.txt | cut -d ',' -f 1 | anew $subs_path/subs.txt

echo '--------------------------------------------'
echo '--------------------------------------------'

# Assetfinder Scan
echo 'assetfinder scan'
assetfinder -subs-only $url | anew $subs_path/subs.txt


echo '--------------------------------------------'
echo '--------------------------------------------'

#Github Sub Scraping
echo 'github scan'
github-subdomains -d $url -t <github-token> -o $subs_path/ghsubs.txt
cat $subs_path/ghsubs.txt | anew $subs_path/subs.txt
rm $subs_path/ghsubs.txt

### Brute Force Subdomains

# PureDNS Brute Force
echo "Brute forcing subdomains for $url"
puredns bruteforce ~/tools/wordlists/assetnote/subs/subs.txt $url --resolvers ~/tools/resolvers/validated-new -w $subs_path/brute.txt
cat $subs_path/brute.txt | anew subs.txt
dnsx -l $subs_path/subs.txt -json -o $hosts_path/dns.json | jq -r '.a?[]?' | anew $hosts_path/ips.txt | wc -l


### What do these subs map out to? AWS? GCP?

echo "Mapping these subs to hosts"
cat $subs_path/subs.txt | xargs -I{} host {} | anew $hosts_path/host-out.txt

### Port Scanning
cat $hosts_path/ips.txt | naabu -silent -o $portscan_path/naabu.txt


### Host Identification
echo "Begin host discovery"
tew -i $portscan_path/naabu.txt -dnsx $hosts_path/dns.json -vhost | httpx -json | jq -r .url | anew $hosts_path/http.txt

### HTTP Crawling
katana -u $hosts_path/http.txt -json -o $content_path/crawl.txt
cat $content_path/crawl.txt | grep "{" | jq -r .endpoint | anew crawl.txt

### HTTP Responses
tew -i $portscan_path/naabu.txt -dnsx $hosts_path/dns.json -vhost | httpx -sr -srd $content_path/responses

### JS Scraping
cat $content_path/crawl.txt | grep "\.js" | httpx -sr -srd $content_path/js

### Look for some quick wins ###

### File Inclusion
cat crawl.txt | grep "?" | qsreplace "../../../../../etc/passwd" | ffuf -u "FUZZ" -w - -mr "^root:" -od $quick_wins/etcpasswd
cat crawl.txt | grep "?" | qsreplace "../../../../../etc/hosts" | ffuf -u "FUZZ" -w - -mr "^127.0.0.1:" -od $quick_wins/hostsfile



### Calculate Endtime
endtime=$(date +%s)
seconds=$(expr $endtime - $timestamp)
time=""


if [[ "$seconds" -gt 59 ]]
then
    minutes=$(expr $seconds / 60)
    time="$minutes minutes"
else
    time="$seconds seconds"
fi

echo "Scan for $url took $time"
