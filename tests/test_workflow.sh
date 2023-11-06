#!/bin/bash
# a ProTego like workflow script that does the following:
#
# - validate the model (MODEL_ID)
# - calculate risk
# - apply provided ZAP vulnerabilities
# - show changed TWAs
# - calculate risk
# - run recommendations
# - reset vulnerabilities
# - calculate risk
#
# before run the script make sure the MODEL_ID is updated,
# invoke the script with a single parameter, i.e. the zap vulnerability report
#
# results are stored in YYY-MM-DD_hh-mm-<vul name>-results directory

set -euo pipefail

# REQUIRED parameters
#
# - MODEL_ID

start_ts=$(date +%s)

echo "SSM-Adaptor initialise model"

SSM_HOST="http://localhost:17643/api"

MODEL_ID=158dab29fiet509av7689elq8ulsc545linmqa0u3indec7t4qfkqasbpkc46e34npefem6lvcd7fd3mjcdbjuaj8dkok50h9edh5q6

CHANGED_FLAG=0

# check if vulnerabilities argument is provided:
if [ $# -eq 0 ]; then
    echo "No vulnerabilities argument supplied"
    exit 1
fi

function validate_model() {
    echo "validating model force"
    curl -sX 'GET' \
        ${SSM_HOST}/models/${MODEL_ID}/validate-model?force_mode=true \
        -H 'accept: application/json'
}

function calculate_model_risk_full() {
    echo "calculating model risk with MS response for $1:" | tee -a $REPORT
    curl -s 'GET' \
        ${SSM_HOST}/models/${MODEL_ID}/calc-risk-vector-full \
        -H 'accept: application/json' | jq . | tee $DIR_LOC/$1.json
    echo "" >> ${REPORT}
}

function calculate_model_risk() {
    echo "calculating model risk:"
    echo "calculating model risk $1:" | tee -a $REPORT
    curl -s 'GET' \
        ${SSM_HOST}/models/${MODEL_ID}/calc-risk-vector \
        -H 'accept: application/json' | jq . | tee -a ${REPORT}
    echo "" >> ${REPORT}
}

function list_twa_changes() {
    echo "list TWA changes:" | tee -a ${REPORT}

    twa_changes=$(curl -s 'GET' \
        ${SSM_HOST}/models/${MODEL_ID}/list-changed-twas \
        -H 'accept: application/json' | jq . )

    echo "TWA changes: $twa_changes" | tee -a $REPORT

    if [ "$twa_changes" == "[]" ]; then
        CHANGED_FLAG=1;
    fi

    echo "" >> ${REPORT}
}

function fetch_model_risk() {
    echo "fetch model risk vector $1:" | tee -a $REPORT
    curl -sX 'GET' \
        ${SSM_HOST}/models/${MODEL_ID}/fetch-risk-vector \
        -H 'accept: application/json' | jq . | tee -a ${REPORT}
    echo "" >> ${REPORT}
}

function update_vulnerabilities() {

    vulnerability=$1

    echo "update OpenVAS vulnerability from ${vulnerability}" | tee -a ${REPORT}
    curl -sX POST \
        ${SSM_HOST}/models/${MODEL_ID}/asset/vulnerability \
        -H  "accept: */*" \
        -H  "Content-Type: application/json" \
        -d @${vulnerability}
}

function update_zap_vulnerabilities() {

    vulnerability=$1
    auth_flag=$2

    echo "update ZAP vulnerability from ${vulnerability}" | tee -a ${REPORT}
    curl -sX POST \
        ${SSM_HOST}/models/${MODEL_ID}/asset/zap-vulnerability?authenticated_scan=${auth_flag} \
        -H  "accept: */*" \
        -H  "Content-Type: application/json" \
        -d @${vulnerability}
}

function run_recommendations() {
    echo "run recommendations algorithm" | tee -a $REPORT
    loop_delay=30
    jid=$(curl -sX 'POST' \
        ${SSM_HOST}/models/${MODEL_ID}/calc-risks \
        -H 'accept: application/json' \
        -d '' | jq ".jid" | tr -d '"')
    echo "JOB id: $jid" | tee -a $REPORT
    job_status="submitted"
    while : ; do
        job_status=$(curl -s ${SSM_HOST}/models/describe/task-status/${jid} \
             -H 'accept: application/json' | jq ".status" | tr -d '"')
        echo "JOB STATUS: $job_status, waiting for ${loop_delay} sec ..."
        if [ "$job_status" == "FINISHED" ]; then
           break
        fi
        sleep $loop_delay
    done
    echo "recommendations finished" | tee -a $REPORT
    sleep 1
    echo "downloading risk calculation" | tee -a $REPORT
    curl -s ${SSM_HOST}/models/download/risk/${jid} \
        -H 'accept: application/json' | jq . | tee $DIR_LOC/risk_vector_full.json
    echo "downloading recommendations" | tee -a $REPORT
    curl -s ${SSM_HOST}/models/download/recommendations/${jid} \
        -H 'accept: application/json' | jq . | tee $DIR_LOC/recommendations.json
 }

function reset_vulnerabilities() {
    echo "reset vulnerabilities" | tee -a $REPORT
    curl -sX 'POST' \
        ${SSM_HOST}/models/${MODEL_ID}/reset-vulnerabilities \
        -H 'accept: application/json' \
        -d ''
}

function check_job_status() {
    jid=$1
    echo "check status for $jid"
    jstatus=$(curl -s ${SSM_HOST}/models/describe/task-status/${jid} \
        -H 'accept: application/json' | jq ".status")
    echo "$jstatus"
}

# create directories
TIME=`date +%Y-%m-%d_%H-%M`
VULNERABILITY=$(basename $1)
DIR_LOC="$TIME-${VULNERABILITY%.*}-results"
mkdir -p $DIR_LOC
REPORT="$DIR_LOC/report.txt"

# copy vulnerabilities to reports
cp "$1" $DIR_LOC

echo "initialising model for $1"
validate_model

echo ""
calculate_model_risk_full "initial_risk_full"

echo ""
fetch_model_risk "initial"

echo ""
#update_zap_vulnerabilities $1 "False"
update_vulnerabilities $1

echo ""
list_twa_changes

if [ $CHANGED_FLAG -eq 0 ]; then
    echo "TWAs changes observed" | tee -a $REPORT
    echo ""
    calculate_model_risk_full "vul_risk_full"
    echo ""
    fetch_model_risk "risk after vulnerabilities applied"

    #exit

    echo ""
    run_recommendations

    #echo "$jid"
    calculate_model_risk "risk vector after recommendations"

    echo ""
    reset_vulnerabilities
    echo ""

    calculate_model_risk "reset"
    echo ""
else
    echo "No TWA changes observed, skipping recommendation part" | tee -a $REPORT
fi

end_ts=$(date +%s)

echo "elapsed time: $(( end_ts - start_ts )) sec" | tee -a $REPORT
