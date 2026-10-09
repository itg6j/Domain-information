#!/bin/bash

read -r -p "[+] Enter Domain : " DOMAIN
if [[ -z "$DOMAIN" ]]; then
        echo "[+] Error : Enter Domain"
        exit 1
fi

folder="target-$DOMAIN"
mkdir -p "$folder"
folderStatus="status"
mkdir -p "$folder/$folderStatus"
echo -e "[+] Target is $DOMAIN"
echo -e "[+] Fetching Subdomain from crt.sh .."

statusFromcurl=$(curl -s -o /dev/null -w "%{http_code}" https://crt.sh)

if [[ "$statusFromcurl" == "200" ]]; then 
        curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u > "$folder/all_subdomains.txt"
        echo "[+] subdomain saved to $folder/all_subdomains.txt"
else 
        echo "[+] crt.sh status code is not 200"
        read -r -p "[+] Do you want bruteforce for subdomain ?? : " dirbuster
        if [[ "$dirbuster" == "y" || "$dirbuster" == "Y" ]]; then 
                read -r -p "[+] Enter path subdomain : " wordlistforbrute 
                if [[ ! -f "$wordlistforbrute" || -z "$wordlistforbrute" ]]; then
                        echo "[+] Not found file wordlist"
                        exit 1
                fi
                echo "[+] starting ffuf bruteforce ..."
                ffuf -w "$wordlistforbrute" -u "https://FUZZ.$DOMAIN" -s | sed "s/$/.$DOMAIN/" | sort -u > "$folder/all_subdomains.txt"
        else
                read -r -p "[+] File exists / manual file present? (y/n) : " answeryn
                if [[ "$answeryn" == "y" || "$answeryn" == "Y" ]]; then
                        if [[ ! -f "$folder/all_subdomains.txt" ]]; then
                                echo "[+] Please ensure $folder/all_subdomains.txt exists before continuing."
                                exit 1
                        fi
                else
                        echo "[+] Exiting: No subdomain file to process."
                        exit 1
                fi
        fi
fi

if [[ -f "$folder/all_subdomains.txt" && -s "$folder/all_subdomains.txt" ]]; then
        echo -e "\n[+] Starting httpx Probing & Categorization..."
        
        httpx -l "$folder/all_subdomains.txt" -sc -silent -o "$folder/$folderStatus/httpx_raw.txt"

        grep " \[200\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/200.txt"
        grep " \[201\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/201.txt"
        grep " \[202\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/202.txt"
        grep " \[204\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/204.txt"
        grep " \[301\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/301.txt"
        grep " \[302\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/302.txt"
        grep " \[307\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/307.txt"
        grep " \[308\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/308.txt"
        grep " \[400\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/400.txt"
        grep " \[401\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/401.txt"
        grep " \[403\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/403.txt"
        grep " \[404\]" "$folder/$folderStatus/httpx_raw.txt" | awk '{print $1}' > "$folder/$folderStatus/404.txt"

        echo "[+] Results Categorized:"
        echo "   ├── 200 Pages: $(wc -l < "$folder/$folderStatus/200.txt") -> $folder/$folderStatus/200.txt"
        echo "   ├── 201 Pages: $(wc -l < "$folder/$folderStatus/201.txt") -> $folder/$folderStatus/201.txt"
        echo "   ├── 202 Pages: $(wc -l < "$folder/$folderStatus/202.txt") -> $folder/$folderStatus/202.txt"
        echo "   ├── 204 Pages: $(wc -l < "$folder/$folderStatus/204.txt") -> $folder/$folderStatus/204.txt"
        echo "   ├── 301 Pages: $(wc -l < "$folder/$folderStatus/301.txt") -> $folder/$folderStatus/301.txt"
        echo "   ├── 302 Pages: $(wc -l < "$folder/$folderStatus/302.txt") -> $folder/$folderStatus/302.txt"
        echo "   ├── 307 Pages: $(wc -l < "$folder/$folderStatus/307.txt") -> $folder/$folderStatus/307.txt"
        echo "   ├── 308 Pages: $(wc -l < "$folder/$folderStatus/308.txt") -> $folder/$folderStatus/308.txt"
        echo "   ├── 400 Pages: $(wc -l < "$folder/$folderStatus/400.txt") -> $folder/$folderStatus/400.txt"
        echo "   ├── 401 Pages: $(wc -l < "$folder/$folderStatus/401.txt") -> $folder/$folderStatus/401.txt"
        echo "   ├── 403 Pages: $(wc -l < "$folder/$folderStatus/403.txt") -> $folder/$folderStatus/403.txt"
        echo "   └── 404 Pages: $(wc -l < "$folder/$folderStatus/404.txt") -> $folder/$folderStatus/404.txt"
        echo -e "\n[+] Starting DNS Enumeration (dig)..."
        while read -r sub; do
                clean_sub=$(echo "$sub" | sed -e 's|^[^:]*://||' -e 's|/.*$||')
                
                cname=$(dig +short CNAME "$clean_sub")
                ips=$(dig +short A "$clean_sub")
                
                first_ip=$(echo "$ips" | grep -v '\.$' | head -n1)
                provider="Unknown / No A Record"

                if [[ -n "$first_ip" ]]; then
                        raw_whois=$(timeout 3 whois "$first_ip" 2>/dev/null)
                        provider=$(echo "$raw_whois" | grep -iE 'org-name|orgname|netname|owner|descr' | head -n1 | awk -F':' '{print $2}' | xargs)
                        
                        if [[ -z "$provider" ]]; then
                                provider="Provider Data Unavailable"
                        fi
                fi

                if [[ -n "$cname" ]]; then
                        echo "$clean_sub CNAME -> $cname" >> "$folder/$folderDNS/cnames.txt"
                fi
                
                echo "$clean_sub | IPs: $(echo $ips | tr '\n' ' ') | Provider: $provider" >> "$folder/$folderDNS/dns_summary.txt"

        done < "$folder/all_subdomains.txt"

        echo "[+] DNS Analysis Completed:"
        echo "   ├── CNAME Records: $folder/$folderDNS/cnames.txt"
        echo "   └── Full DNS & Provider Summary: $folder/$folderDNS/dns_summary.txt"

        if [[ -f "$folder/$folderDNS/dns_summary.txt" ]]; then
                echo -e "\n[+] Top Identified Infrastructure Providers:"
                awk -F'| Provider: ' 'NF>1 {print $2}' "$folder/$folderDNS/dns_summary.txt" | sort | uniq -c | sort -nr | head -n 5 | while read -r count name; do
                        echo "   ├── $name: $count subdomain(s)"
                done
        fi
else
        echo -e "[+] No subdomains found to process with httpx."
fi
