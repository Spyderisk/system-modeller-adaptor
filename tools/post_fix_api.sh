#!/bin/bash

# simple script to prefix __init__.py include api paths
# run ./post_fix_api.sh <codegen_client_v2/ssm_api_client_v2>
#

presuffix=$(basename $1)

sed -i "s/ api\./ ${presuffix}.api./" $1/__init__.py

sed -i "s/ api\./ ${presuffix}.api./" $1/api/__init__.py

