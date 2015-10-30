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
            rname_regex = r'rule\s+(.*[^\s{])'
            include_regex = re.search(r'include\s+\".*?\"', self.file)
            import_regex = r'import\s+\"(.*?)\"'

            if re.search(script_regex, self.filename) is not None:
              return
            if self.remove_duplicates:
              if hashfile(open(rfile, 'rb'), hashlib.sha256()) in self.hashes:
                mdir = "Dup_files"
                self.folderize(mdir)
                return
              else:
                self.hashes.append(hashfile(open(rfile, 'rb'), hashlib.sha256()))

            if self.remove_duplicates:
              for match in re.finditer(rule_regex, self.file):
                if hashlib.sha256(match.group(1)).hexdigest() in self.rulehashes:
                  mdir = "Dup_rules"
                  self.folderize(mdir)
                  return
                else:
                  self.rulehashes.append(hashlib.sha256(match.group(1)).hexdigest())

            if self.remove_duplicates:
              for match in re.finditer(rname_regex, self.file, re.MULTILINE):
                if re.search(r':', match.group(1)):
                  rule_name = re.search(r'(^\w+)', match.group(1)).group(1)
                else:
                  rule_name = match.group(1)
                if hashlib.sha256(rule_name).hexdigest() in self.rulenames:
                  mdir = "Dup_rulenames"
                  self.folderize(mdir)
                  return
                else:
                  self.rulenames.append(hashlib.sha256(match.group(1)).hexdigest())

            for match in re.finditer(import_regex, self.file, re.MULTILINE):
              if not module_exists(match.group(1)):
                #print "Folderizing %s to Imports..." % match.group(1) #DEBUG
                mdir = "Imports"
                self.folderize(mdir)
                return
              else:
                pass

            if include_regex:
              mdir = "Meta_files"
            elif re.search(apt_regex, self.filename) is not None:
              mdir = "APT"
            elif re.search(android_regex, self.filename) is not None:
              mdir = "Android"
            elif re.search(det_regex, self.filename) is not None:
              mdir = "Anti_VM"
            elif re.search(rat_regex, self.filename) is not None:
              mdir = "RAT"
            elif re.search(troj_regex, self.filename) is not None:
              mdir = "Malware"
            elif re.search(misc_regex, self.filename) is not None:
              mdir = "Misc"
            else:
              #print "No match in filenames, starting to parse file..." #DEBUG
              try:
                mdir = self.parseFile()
              except AttributeError, e:
                print e
              #print mdir #DEBUG
            self.folderize(mdir)
            return

        except:
            e = sys.exc_info()[0]
            error = "Error processing file %s : %s" % (self.filename, e)
            print error
        #print "At the end of process_files() now." #DEBUG


    def parseFile(self):
      #print "Now parsing file %s" % self.filename #DEBUG
      maltype_regex = re.search(r'maltype = \"(.*?)\"', self.file)
      general_regex = re.search(r'[Ii][Dd][Ee][Nn][Tt][Ii][Ff]([Yy]|[Ii][Ee])', self.file) #needs work
      file_regex = re.search(r'[Ff][Ii][Ll][Ee]', self.file)

      malware_regex = '[Tt][Rr][Oo][Jj][Aa][Nn]|[Mm][Aa][Ll][Ww][Aa][Rr][Ee]'
      tool_regex = '\s+[Tt][Oo][Oo][Ll]|[Bb][Rr][Uu][Tt][Ee]|[Uu][Tt][Ii][Ll][Ii][Tt][Yy]'
      ratty_regex = '[Rr][Aa][Tt]'
      apty_regex = '[Aa][Pp][Tt]'

      #print "Regexes good, starting the matching..." #DEBUG
      try:
        if maltype_regex:
          if maltype_regex.group(1) == "Remote Access Trojan":
            target_dir = "RAT"
          elif re.search(apty_regex, maltype_regex.group(1)) is not None:
            target_dir = "APT"
          elif re.search(malware_regex, maltype_regex.group(1)) is not None:
            target_dir = "Malware"
          else:
            target_dir = maltype_regex.group(1)
            target_dir = ''.join(e for e in target_dir if e.isalnum())
            return target_dir
        elif re.search(malware_regex, self.file) is not None:
          target_dir = "Malware"
        elif re.search(tool_regex, self.file) is not None:
          target_dir = "Hacking_tools"
        elif re.search(ratty_regex, self.file) is not None:
          target_dir = "RAT"
        elif general_regex is not None and file_regex is not None:
          target_dir = "General"
        else:
          target_dir = "Misc"

        return target_dir
      except TypeError, e:
        print e

    def folderize(self, mdir):
        try:
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

def module_exists(module_name):
    try:
        __import__(module_name)
    except ImportError:
        return False
    else:
        return True


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
      f.closed
