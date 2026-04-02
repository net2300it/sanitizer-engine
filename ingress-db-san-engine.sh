#!/bin/bash
# Import the library function from the file you just created
source ./lib/db_lib.sh

# 1. READ only the latest record with status PENDING (Task Requirement)
# -N -s removes table headers and formatting for easy parsing
JOB_DATA=$(docker exec -i mysql_sanitizer mysql -u user -ppassword sanitizer_db -N -s -e \
"SELECT id, user_id, file_name FROM job_request WHERE status = 'PENDING' ORDER BY id DESC LIMIT 1;")

if [ -z "$JOB_DATA" ]; then
    echo "No pending jobs found in job_request table."
    exit 0
fi

# Parse the data into variables
read -r JOB_ID USER_ID FILE_NAME <<< "$JOB_DATA"

echo "Found Pending Job ID: $JOB_ID | File: $FILE_NAME | User: $USER_ID"

# 2. STATUS UPDATES using the library function (Task Requirement)
echo "Step 1: Initializing..."
insert_report_status "INITIALIZING" "Started processing $FILE_NAME" "$JOB_ID" "$USER_ID"

echo "Step 2: Processing..."
sleep 2 # Simulating sanitization time
insert_report_status "PROCESSING" "Applying sanitization rules to $FILE_NAME" "$JOB_ID" "$USER_ID"

echo "Step 3: Finalizing..."
# Mark the original request as COMPLETED in the job_request table
docker exec -i mysql_sanitizer mysql -u user -ppassword sanitizer_db -e \
"UPDATE job_request SET status = 'COMPLETED' WHERE id = $JOB_ID;"

insert_report_status "SUCCESS" "Sanitization finished for $FILE_NAME" "$JOB_ID" "$USER_ID"

echo "Execution Complete. Status reports inserted into job_execution_report."
