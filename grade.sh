#!/bin/bash

######## Variable globals -> ########
# The file containing the "main" entry point for the program.
# In C or C++, this is the file containing the main() function
# In Python, this is whichever file you run via python3 whatever.py
# In Bash, this is whichever file you run via bash whatever.sh
# In Rust, this is src/main.rs
main_file="proxy.py"

# Any arguments you want passed to the main driver, upon excution.
# If you do not have any arguments, just leave as an empty string, ""
main_file_arguments=""

# The language that the assignment is written in.  Currently supported
# options are "cpp", "python", "bash", "rust"
language="python"

# Whether or not to score the student using a static analyzer.
# For Python, this is the mypy type-checker.
# For C or C++, this is cppcheck.
# For Bash, this is shellcheck
# Not needed at all with rust's awesome compiler!
enable_static_analysis=true

# Whether or not to score the student using an autoformatter (dock points
# if not formatted correctly).
# For Python, this is black.
# For C++, this is clang-format.
# For Bash, this is shfmt
# For Rust, this is rustfmt
enable_format_check=true

# Whether or not to use fuzzy or ridig diffs
# If you choose true, fuzzy diffs will give partial credit.
# This can be helpful for string-heavy assignments,
# where correctness is reasonable to estimate statistically.
# If you choose false, rigid diffs will be all-or-none.
# This is helpful when the assignment is mathy,
# where correctness is not reasonable to estimate statistically.
fuzzy_partial_credit=true

# The timeout duration in seconds for killing a student process.
# This can limit infinite run-times.
# For computationally expensive operations, you may increase this time as desired.
process_timeout=15

# The file to which the final grade is written
# This file can be saved as as artifact in gitlb CI/CD, and used to upload scores to Canvas using assigner.
student_file="results.txt"
######## <- Variable globals ########

######## File and type existence tests -> ########
# Load the specified assosicative array with files you want to check for the existence of.
# Key is the file, and Value must be a sub-string within what is produced by the bash command:
# $ file file.whatever
declare -A file_arr
file_arr=(
    ["iactuallytestedthis-proxy.png"]="PNG image data"
)
######## <- File and type existence tests ########

######## Custom tests -> ########
# Any tests other than the unit tests and the stdout diff tests belong here,
# and must be bash functions whose names begin with "custom_test".
# Custom tests should report their score by assigning their result (0-100)
# to the custom_test_score, e.g.:
# custom_test_score=100
# Custom tests are performed alphabetically,
# so number them if you want them in order.

custom_test_1() {
	tmp_score=100
    DIR='goal_files/'
    OUT_DIR='received_files/'
	rm -rf ./"$DIR"/*.html
	rm -rf ./"$OUT_DIR"/*.html

	FILES=(  )
	for (( i=0; i<10; i++ )); do
		FILES=( ${FILES[@]} ""$i".html" )
	done

	for file in "${FILES[@]}"; do
		datalen="$(($(($RANDOM%100000))+1))"
		touch $DIR$file
		data="$(tr -dc [:alnum:] < /dev/urandom | head -c "$datalen")"
		echo "$data" > $DIR$file
	done

	# start the server
	python3 grader_server.py &
	SERV_PID=$!
	# start the proxy
	python3 proxy.py &
	PROXY_PID=$!
	sleep 2

	for file in "${FILES[@]}"; do
		echo "$file wget output:"
		if ! wget http://localhost:8923/$file -e use_proxy=yes -e http_proxy=localhost:6789 --read-timeout=1 --tries=1 -O $OUT_DIR$file; then
			tmp_score=0
		fi
		echo "$file diff output:"
		if ! diff -yZB $OUT_DIR$file $DIR$file; then
			tmp_score=0
		fi
	done
	rm -rf ./"$DIR"/*.html
	rm -rf ./"$OUT_DIR"/*.html
	kill $PROXY_PID $SERV_PID
    custom_test_score=$tmp_score
}
######## <- Custom tests ########

source .admin_files/grade_backend.sh
