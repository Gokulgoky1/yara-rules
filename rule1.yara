import "hash"
rule hash_scan_success
{
	meta:
		author="Gokul G R"
		description="Scanning for a local file with md5 hash"
	condition:
		hash.md5(0, filesize) == "747785df1b75effd9c19477b5c825823" // paste hash of any file you want to scan
}