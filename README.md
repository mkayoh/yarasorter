# yarasorter
Simple Python script for sorting out Yara rules and checking for duplicates.
One good project to pair with this one is [unusedPhd/GithubDownloader](https://github.com/unusedPhD/GithubDownloader) that you can use for downloading all known Yara rules in Github.

## Usage

`./sorter.py -f <yara_files> -o <OUTPUT_DIR> -r`

Omit the `-r` if you wish to just sort the rules without checking for duplicates.

Use the argument `-t` to test the rules after sorting in Yara.

Right now the rules get sorted into six different categories:

* Android
* APT
* Anti-VM
* Malware
* Misc
* RAT

Also if the rulefile has *maltype* field(s) in them, a folder will be created based on the first occurrence for the rulefile.


The duplicate checking option will sort the possibly duplicate rules in the following folders:

* Dup_files
	- Files that already been processed at least once before
* Dup_rules
	- Files that contain rules that have already been sorted
* Dup_rulenames
	- Files that contain rules with already used rulenames

There are three special folders: 

* Meta_files
* Imports
* Broken_rules

The first is reserved for Yara's meta-rulefiles. If you use the aforementioned GithubDownloader it'll download a bunch of meta files as well that are used just for invoking other rulefiles. Running Yara with multiple of these usually spells trouble and because of this the script will pick out all of the files that have the string *include "rule_file"* in them.
The second one is for rulefiles that import a Python module that isn't present on the system where the script is ran.

Finally the third one is only created if you use the `-t` argument when running the sorter and all rules that cause an error in Yara for one reason or another are places in this folder after the initial sorting.

## Disclaimer

The sorting system isn't nearly as perfect right now as I would like and it relies heavily on hacked together regex tricks. Unfortunately since Yara rule files don't have that strict syntax for creating rules it's difficult to refine them further, but if I get any good ideas I might add more options or filters.

