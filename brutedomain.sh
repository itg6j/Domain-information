#!/bin/bash
read -p "Enter the target domain (e.g., inlanefreight.htb): " domain
read -p "Enter the DNS server IP (e.g., 10.129.14.128): " dns_server
read -p "Enter the path to the wordlist file: " wordlist_path
if [ ! -f "$wordlist_path" ]; then
    echo "[-] Error: Wordlist file not found at '$wordlist_path'!"
    exit 1
fi
echo "[+] Starting enumeration for domain: $domain using DNS: $dns_server..."
output_file="subdomains_results.txt"
> "$output_file"
for sub in $(cat "$wordlist_path"); do
    result=$(dig "$sub.$domain" "@$dns_server" +short)
    if [ -n "$result" ]; then
        echo "[+] Found: $sub.$domain -> $result"
        echo "$sub.$domain" >> "$output_file"
    fi
done

echo "[+] Finished! Valid subdomains saved in '$output_file'."
