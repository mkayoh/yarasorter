# yarasorter
Simple Python script for sorting out Yara rules and checking for duplicates.
One good project to pair with this one is [unusedPhd/GithubDownloader](https://github.com/unusedPhD/GithubDownloader) that you can use for downloading all known rules in Github.

## Usage

`./sorter.py -f <yara_files> -o <OUTPUT_DIR>`

If you wish to sort the files as well use the argument `-r`

Right now the rules get sorted into six different categories:

* Android
* APT
* Anti-VM
* Malware
* Misc
* RAT

The duplicate checking option will sort the possibly duplicate rules in the following folders:

* Dup_files
	- Files that already been processed at least once before
* Dup_rules
	- Files that contain rules that have already been sorted
* Dup_rulenames
	- Files that contain rules with already used rulenames

## Disclaimer

The sorting system isn't nearly as perfect right now as I would like and it relies heavily on hacked together regex tricks. Unfortunately since Yara rule files don't have that strict syntax for creating rules it's difficult to refine them further, but if I get any good ideas I might add options or filters.

