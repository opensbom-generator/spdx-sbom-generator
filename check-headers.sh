#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0

# A simple script that scans the go files checking for the license header.
# Exits with a 0 if all source files have license headers
# Exits with a 1 if one or more source files are missing a license header

# These are the file patterns we should exclude - these are typically transient files not checked into source control
exclude_pattern='vendor|node_modules|.venv|.pytest_cache|.idea|version.txt'

files=()
echo "Scanning source code..."
# Adjust this filters based on the source files you are interested in checking
# Loads all the filenames into an array
# We need optimize this, possibly use: -name '*.go' -o -name '*.txt' - not working as expected on mac
echo "Searching go files..."
files+=($(find . -name '*.go' -print | egrep -v ${exclude_pattern}))
echo "Searching python files..."
files+=($(find . -name '*.py' -print | egrep -v ${exclude_pattern}))
echo "Searching sh files..."
files+=($(find . -name '*.sh' -print | egrep -v ${exclude_pattern}))
echo "Searching make files..."
files+=($(find . -name 'Makefile' -print | egrep -v ${exclude_pattern}))
echo "Searching txt files..."
files+=($(find . -name '*.txt' -print | egrep -v ${exclude_pattern}))
echo "Searching yaml|yml files..."
files+=($(find . -name '*.yaml' -print | egrep -v ${exclude_pattern}))
files+=($(find . -name '*.yml' -print | egrep -v ${exclude_pattern}))
files+=($(find . -name '.gitignore' -print | egrep -v ${exclude_pattern}))
echo "Searching SQL files..."
files+=($(find . -name '*.sql' -print | egrep -v ${exclude_pattern}))

# This is the copyright line to look for - adjust as necessary
copyright_line="SPDX-License-Identifier: Apache-2.0"

# Flag to indicate if we were successful or not
missing_license_header=0

# For each file...
echo "Checking ${#files[@]} source code files for the license header..."
for file in "${files[@]}"; do
  # echo "Processing file ${file}..."

  # Header is typically one of the first few lines in the file...
  head -4 "${file}" | grep -q "${copyright_line}"
  # Find it? exit code value of 0 indicates the grep found a match
  exit_code=$?
  if [[ ${exit_code} -ne 0 ]]; then
    echo "${file} is missing the license header"
    # update our flag - we'll fail the test
    missing_license_header=1
  fi
done

# Summary
if [[ ${missing_license_header} -eq 1 ]]; then
  echo "One or more source files is missing the license header."
else
  echo "License check passed."
fi

# Exit with status code 0 = success, 1 = failed
exit ${missing_license_header}
