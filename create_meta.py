#!/usr/bin/python

import os, re, sys
import argparse

if __name__ == '__main__':

  parser = argparse.ArgumentParser(prog="sorter", description = "Yara rules sorter")
  parser.add_argument('-f','--file', nargs='*', required = True, help = "Full path to the yara rule(s) to sort, use wildcard (*)")
  parser.add_argument("-o", "--output-dir", default = "", help = "Output directory where to sort the rules, by default the current working directory")
  if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

  try:
      args = parser.parse_args()
  except IOError:
      e = sys.exc_info()[1]
      print 'The file provided could not be found. Error: %s' % e
      sys.exit(1)
  yara = os.path.join(args.output_dir, 'rules.yara')
  
  for rfile in args.file:
    if os.path.isfile(rfile):
      rfile = re.search(r'.*\/(.*)$', rfile).group(1)
      print rfile
      with open(yara, 'a+') as f:
        f.write("include " +"\"" + rfile + "\"\n")
      f.closed