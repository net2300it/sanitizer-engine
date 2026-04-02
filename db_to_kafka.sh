#!/bin/bash

# 1. READ from the job_request table
JOB_DATA=$(docker exec -i mysql_sanitizer mysql -u user -ppassword sanitizer_db -N -s -e \
"SELECT id, user_id, file_name, file_content FROM job_request WHERE status = 'PENDING' ORDER BY id DESC LIMIT 1;")

if [ -z "$JOB_DATA" ]; then
    echo "No pending jobs found."
    exit 0
fi

# Parse the data into variables
read -r JOB_ID USER_ID FILE_NAME FILE_CONTENT <<< "$JOB_DATA"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# 2. CONSTRUCT the JSON payload
JSON_PAYLOAD="{\"metadata\": {\"user_id\": \"$USER_ID\", \"timestamp\": \"$TIMESTAMP\", \"source\": \"database_ingress\"}, \"payload\": {\"job_id\": \"$JOB_ID\", \"file_name\": \"$FILE_NAME\", \"content\": \"$FILE_CONTENT\"}}"

# 3. SEND the JSON to the kafka topic
echo "$JSON_PAYLOAD" | docker exec -i dev-kafka-1 kafka-console-producer --bootstrap-server localhost:9092 --topic sanitizer_in

if [ $? -eq 0 ]; then
    echo "Successfully sent JSON to Kafka topic: sanitizer_in"
    # Update DB so we don't process it again
    docker exec -i mysql_sanitizer mysql -u user -ppassword sanitizer_db -e "UPDATE job_request SET status = 'PROCESSED' WHERE id = $JOB_ID;"
fi
