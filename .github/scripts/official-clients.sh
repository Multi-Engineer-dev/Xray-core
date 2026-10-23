#!/usr/bin/env bash
set -euo pipefail
destination="${1:?usage: official-clients.sh DESTINATION}"
mkdir -p "$destination"
while read -r tag archive_hash binary_hash; do
  directory="$destination/$tag"
  mkdir -p "$directory"
  curl --fail --location --retry 3 "https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-64.zip" -o "$directory/Xray-linux-64.zip"
  echo "$archive_hash  $directory/Xray-linux-64.zip" | sha256sum -c -
  unzip -q -o "$directory/Xray-linux-64.zip" -d "$directory"
  echo "$binary_hash  $directory/xray" | sha256sum -c -
  "$directory/xray" version
done <<'CLIENTS'
v25.12.8 97f20fed49750c24fc389c2946549ba2a374907e07e9adb2ce75799dd80088d9 fc38e30d5f3810a5bca03c59918c34f87a1370449a14801725c6b702751e1601
v26.3.27 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae 8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed
v26.10.21 0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978 a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e
CLIENTS
mkdir -p resources
# Use the verified newest archive's fixture files, independent of cache state.
cp "$destination/v26.10.21/geoip.dat" resources/geoip.dat
cp "$destination/v26.10.21/geosite.dat" resources/geosite.dat
