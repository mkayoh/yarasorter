#!/usr/bin/python

__author__ = 'mkayoh'
import os, sys, re
import argparse
import shutil
import hashlib

class YaraSorter:
    def __init__(self, file, fullpath, filename, output, remove_duplicates, hashes, rulehashes, rulenames):
        self.file = file
        self.fullpath = fullpath
        self.filename = filename
        self.output = output
        self.remove_duplicates = remove_duplicates
        self.hashes = hashes
        self.rulehashes = rulehashes
        self.rulenames = rulenames

    def process_files(self): 

        try:
            script_regex = os.path.basename(__file__)
            apt_regex = '^[Aa][Pp][Tt]'
            det_regex = '[Dd][Ee][Tt][Ee][Cc][Tt]|[Dd][Ee][Bb][Uu][Gg]|[Cc][Hh][Ee][Cc][Kk]'
            rat_regex = '[Rr][Aa][Tt]'
            troj_regex = '[Tt][Rr][Oo][Jj][Aa][Nn]|[Mm][Aa][Ll][Ww][Aa][Rr][Ee]'
            android_regex = '[Aa][Nn][Dd][Rr][Oo][Ii][Dd]'
            misc_regex = '[Mm][Ii][Ss][Cc]'
            rule_regex = '\{([\S\s]*)\}'
            rname_regex = r'rule\s+(.*\S{1})\r*?\n*?$'

            if re.search(script_regex, self.filename) is not None:
              self.file.close()

            if self.remove_duplicates:
              if hashfile(open(rfile, 'rb'), hashlib.sha256()) in self.hashes:
                mdir = "Dup_files"
                self.folderize(mdir)
                self.file.close()
              else:
                self.hashes.append(hashfile(open(rfile, 'rb'), hashlib.sha256()))

            if self.remove_duplicates:
              for match in re.finditer(rule_regex, self.file):
                if hashlib.sha256(match.group(1)).hexdigest() in self.rulehashes:
                  mdir = "Dup_rules"
                  self.folderize(mdir)
                  self.file.close()
                else:
                  self.rulehashes.append(hashlib.sha256(match.group(1)).hexdigest()) #something fucky going on

            if self.remove_duplicates:
              for match in re.finditer(rname_regex, self.file, re.MULTILINE):
                if hashlib.sha256(match.group(1)).hexdigest() in self.rulenames:
                  mdir = "Dup_rulenames"
                  self.folderize(mdir)
                  self.file.close()
                else:
                  self.rulenames.append(hashlib.sha256(match.group(1)).hexdigest())
            
            if re.search(apt_regex, self.filename) is not None:
              mdir = "APT"
              self.folderize(mdir)
              self.file.close()
            elif re.search(android_regex, self.filename) is not None:
              mdir = "Android"
              self.folderize(mdir)
              self.file.close()
            elif re.search(det_regex, self.filename) is not None:
              mdir = "Anti_VM"
              self.folderize(mdir)
              self.file.close()
            elif re.search(rat_regex, self.filename) is not None:
              mdir = "RAT"
              self.folderize(mdir)
              self.file.close()
            elif re.search(troj_regex, self.filename) is not None:
              mdir = "Malware"
              self.folderize(mdir)
              self.file.close()
            elif re.search(misc_regex, self.filename) is not None:
              mdir = "Misc"
              self.folderize(mdir)
              self.file.close()
            else:
              #print "No match in filenames, starting to parse file..." #DEBUG
              mdir = self.parseFile()
              #print mdir #DEBUG
              self.folderize(mdir)
              self.file.close()

        except:
            e = sys.exc_info()[0]
            error = "Couldn't open file %s for reading. Error %s" % (self.filename, e)  
        #print "At the end of process_files() now." #DEBUG

    def testFunction(self):
      target_dir = "Derp."
      return target_dir

    def parseFile(self):
      include_regex = re.search(r'include\s\".*?\"', self.file)
      maltype_regex = re.search(r'maltype = \"(.*?)\"', self.file)
      malware_regex = re.search(r'[Tt][Rr][Oo][Jj][Aa][Nn]|[Mm][Aa][Ll][Ww][Aa][Rr][Ee]', self.file)
      tool_regex = re.search(r'\s[Tt][Oo][Oo][Ll]|[Bb][Rr][Uu][Tt][Ee]|[Uu][Tt][Ii][Ll][Ii][Tt][Yy]', self.file)
      ratty_regex = re.search(r'[Rr][Aa][Tt]', self.file)
      apty_regex = '[Aa][Pp][Tt]'
      general_regex = re.search(r'[Ii][Dd][Ee][Nn][Tt][Ii][Ff]([Yy]|[Ii][Ee])', self.file) #needs work
      file_regex = re.search(r'[Ff][Ii][Ll][Ee]', self.file)

      abso_path = os.path.abspath(self.fullpath)
      #print "Starting to read file %s" % abso_path #DEBUG
      try:
        if include_regex:
          target_dir = "Meta_files"
        elif maltype_regex:
          if maltype_regex.group(1) == "Remote Access Trojan":
            target_dir = "RAT"
          elif re.search(apty_regex, maltype_regex.group(1)) is not None:
            target_dir = "APT"
          elif research(malware_regex, malware_regex.group(1)) is not None:
            target_dir = "Malware"
          else:
            target_dir = maltype_regex.group(1)
            target_dir = re.sub(r"[^\w\s]", '', target_dir)
            target_dir = re.sub(r"\s+", '_', target_dir)
        elif malware_regex:
          target_dir = "Malware"
        elif tool_regex:
          target_dir = "Hacking_tools"
        elif ratty_regex:
          target_dir = "RAT"
        elif general_regex and file_regex:
          target_dir = "General"
        else:
          target_dir = "Misc"

        return target_dir

      except IOError, e:
        print e

    def folderize(self, mdir):
        try:
            #check if folder exists, if not create it
            mdir = os.path.join(self.output, mdir)
            if not os.path.exists(mdir):
                  os.makedirs(mdir)
        except:
            e = sys.exc_info()[0]
            error = "Couldn't create the directory %s for %s in output directory. Error %s" % (self.output, self.filename, e)  
            print error
            
        #copy the file to the folder
        filepath = os.path.abspath(self.fullpath)
        mdir = os.path.abspath(mdir)
        mdir = mdir + "/"
        #print filepath #DEBUG
        #print mdir #DEBUG
        try:
          if os.path.exists(mdir):
            #print "The folder exists, copying rules..." #DEBUG
            try:
              shutil.move(filepath, mdir)
            except IOError, e:
              print "Unable to copy file. %s" % e
            #print "Rule copied" #DEBUG
        except:
          e = sys.exc.info()[0]
          print "Error: %s" % (e)

def hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()


if __name__ == '__main__':

  parser = argparse.ArgumentParser(prog="sorter", description = "Yara rules sorter")
  parser.add_argument('-f','--file', nargs='*', required = True, help = "Full path to the yara rule(s) to sort, use wildcard (*) to sort all the rules in a folder")
  parser.add_argument("-o", "--output-dir", default = "", help = "Output directory where to sort the rules, by default the current working directory")
  parser.add_argument("-r", "--remove-duplicates", default = False, action = "store_true", help ="Place the duplicate rulefiles in their separate folders")
  if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

  try:
      args = parser.parse_args()
  except IOError:
      e = sys.exc_info()[1]
      print 'The file provided could not be found. Error: %s' % e
      sys.exit(1)

  hashes = []
  rulehashes = []
  rulenames = []

  for rfile in args.file:
    if os.path.isfile(rfile):
      with open(rfile, 'r') as f:
        file = f.read()
        filename = os.path.basename(f.name)
        yara = YaraSorter(file, f.name, filename, args.output_dir, args.remove_duplicates, hashes, rulehashes, rulenames)
        yara.process_files()
