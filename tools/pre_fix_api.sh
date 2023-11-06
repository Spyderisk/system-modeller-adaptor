#!/bin/bash

# simple script to fix YAML file
# run ./pre_fix_api.sh <YAML>
#

# fix {x}Label names
sed -i "s/ getmLabel/ mLabel/" $1
sed -i "s/ getaLabel/ aLabel/" $1

# fix date-time types
sed -zEi 's/string([^\n]*\n[^\n]*format: )(date-time)/integer\1 int64/g' $1

