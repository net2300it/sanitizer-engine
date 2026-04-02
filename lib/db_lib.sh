#!/bin/bash
insert_report_status() {
    local status="$1"
    local log_msg="$2"
    local job_id="$3"
    local user_id="$4"
    local node_name=$(hostname)

    docker exec -i mysql_sanitizer mysql -u user -ppassword sanitizer_db -e \
    "INSERT INTO job_execution_report (status, execution_log, job_request_id, user_id, execution_node, start_time) 
    VALUES ('$status', '$log_msg', $job_id, $user_id, '$node_name', NOW()) 
    ON DUPLICATE KEY UPDATE status='$status', execution_log='$log_msg', end_time=NOW();"
}
