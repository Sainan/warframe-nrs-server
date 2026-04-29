sun
echo "Further output will be written to log.txt."

echo "=== Start ===" > log.txt
while [[ 1 ]]; do
	LD_LIBRARY_PATH=. ./warframe-nrs-server public >> log.txt
	echo "=== Restart ===" >> log.txt
done
