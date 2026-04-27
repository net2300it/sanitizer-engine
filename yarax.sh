#!/bin/bash

DB_NAME="sanitizer_db"
FILE_TO_SCAN=$1

if [ -z "$FILE_TO_SCAN" ]; then
	echo "Usage: ./yarax.sh <file_path>"
	exit 1
fi

SCAN_RESULTS=$(yara -w rules.yar "$FILE_TO_SCAN")

MATCHES=$(echo "$SCAN_RESULTS" |  awk '{print $1}' | paste -sd "," -)

if [ ! -z "$MATCHES" ]; then
	echo "Malicious activity detected: $MATCHES"
	mysql -h 127.0.0.1 -u root --password='rootpassword' "$DB_NAME" <<EOF
INSERT INTO scan_logs (file_path, rule_match, scan_date)
VALUES ("$FILE_TO_SCAN", "$MATCHES", NOW());
EOF
	echo "Result logged to database."
else
	echo "File is clean."
fi

