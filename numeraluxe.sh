#!/bin/bash

url=$1

if [ ! -d "$url" ]; then
    mkdir -p "$url"
fi

if [ ! -d "$url/recon" ]; then
    mkdir -p "$url/recon"
fi

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder -subs-only "$url" | tee -a "$url/recon/assetfinder-sub.txt"
cat "$url/recon/assetfinder-sub.txt" >> "$url/recon/all-subdomains.txt"
rm "$url/recon/assetfinder-sub.txt"

echo "[+] Harvesting subdomains with subfinder..."
subfinder -d "$url" -silent | tee -a "$url/recon/subfinder-sub.txt"
cat "$url/recon/subfinder-sub.txt" >>  "$url/recon/all-subdomains.txt"
rm "$url/recon/subfinder-sub.txt"

echo "[+] Harvesting subdomains with findomain..."
findomain -t "$url" -q | tee -a "$url/recon/findomain-sub.txt"
cat "$url/recon/findomain-sub.txt" >> "$url/recon/all-subdomains.txt"
rm "$url/recon/findomain-sub.txt"

cat "$url/recon/all-subdomains.txt" | sort | uniq | tee -a "$url/recon/uniq-subdomains.txt"
rm "$url/recon/all-subdomains.txt"

cat "$url/recon/uniq-subdomains.txt" | httpx -mc 200 -silent | tee -a "$url/recon/alive-hosts.txt"
rm "$url/recon/uniq-subdomains.txt"

cat "$url/recon/alive-hosts.txt" | sed 's~^https\?://~~;s~/.*~~' | tee -a "$url/recon/alive-subdomains.txt"
cat "$url/recon/alive-hosts.txt" | waybackurls | tee -a "$url/recon/way-subdomains.txt"
cat "$url/recon/way-subdomains.txt" | sort | uniq | tee -a "$url/recon/uniq-wayback-urls.txt"

gf_patterns=(
    debug_logic
    idor
    img-traversal
    interestingEXT
    interestingparams
    interestingsubs
    jsvar
    lfi
    rce
    redirect
    sqli
    ssrf
    ssti
    xss
)

# Loop through each Gf pattern and apply the command, storing output in different files
for pattern in "${gf_patterns[@]}"; do
    temp_file=$(mktemp)  # Create a temporary file
    gf "$pattern" < "$url/recon/uniq-wayback-urls.txt" > "$temp_file"  # Run gf and store output in the temp file
    mv "$temp_file" "$url/recon/${pattern}_params.txt"  # Rename the temp file to the desired output filename
done
