#!/usr/bin/env python3

import os
import hashlib
import gzip
import argparse
import sys
try:
    import magic
except:
    pass

from tqdm import tqdm

class File:
    def __init__(self,filename:str,hashtypes=['md5']):
        self.filename=filename
        self.file=os.path.basename(filename)
        self.filesize=-1
        self.results={}
        self.filetype=""
        self.errors=[]
        if os.path.isfile(filename):
            if os.access(filename,os.R_OK):
                self.filesize=os.path.getsize(filename)
                if self.filesize >= 0 and ((self.filesize<args.max_file_size) or (args.max_file_size <=0)):
                    hashers=[hashlib.new(hashtype) for hashtype in hashtypes]
                    hpb=tqdm(total=self.filesize,desc=self.file,unit='bytes',leave=False,mininterval=0.5,disable=not args.progress)
                    try:
                        if args.magic : self.filetype=magic.from_file(self.filename,mime=True)
                        with open(filename, 'rb') as f:
                            while True:
                                data = f.read(65536)
                                hpb.update(len(data))

                                if not data:
                                    break
                                else:
                                    for hasher in hashers:
                                        hasher.update(data)
                    except Exception as e:
                        self.errors.append("File could not be read")
                        print(e )
                    self.results={h.name:h.hexdigest() for h in hashers}
                    hpb.close()
                else:
                    self.errors.append("File too big")
            else:
                self.errors.append("Can't read file")
        else:
            self.errors.append("Not a regular file")

    def __str__(self):
        return "{};{};{};{};{}".format(self.filename,self.filesize,self.filetype,str(self.results),str(self.errors))

def log(message,loglevel=2):
    level=["error","info","debug","trace"]
    if loglevel < args.verbosity:
        print("[{}] : {}".format(level[loglevel],message.rstrip()))

def get_filelist(basepath):
    if args.progress : fpb=tqdm(desc="Dicovering Files",unit=' files',mininterval=1)
    filelist=[]
    excludedfolders=[]
    for path,folders,files in os.walk(basepath,topdown=True):
        if args.progress : fpb.update(len(files))
        log("processing path {}".format(path),3)
        log("following folders were found: {}".format(str(folders)),3)

        # remove ignored foldersfrom traversal list
        if args.ignore_dir:
            # skip if path is in ignore list
            if path in args.ignore_dir:
                excludedfolders.append(path)
                folders.clear()
                file.clear()

            # remove subfolders if subfoldernames are in ignorelist
            excluded_subfolders=[x for x in folders if x in args.ignore_dir]
            log("following folders will be excluded: {}".format(str(excluded_subfolders)),2)
            for subfolder in excluded_subfolders :
                folders.remove(subfolder)
                excludedfolders.append(os.path.join(path,subfolder))

        filelist.extend([os.path.join(path,f) for f in files])
    if args.progress : fpb.close()
    return filelist,excludedfolders

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--max-file-size", metavar='<SIZE>', help="Max Size of files to hash in bytes. Set value of <SIZE> <= 0 to disable filtering of large files. This will increase the time required. Default value is 50M.", type=int, default=(50*1024*1024), required=False)
    parser.add_argument("-d", "--ignore-dir", metavar='<NAME>', help="Ignore directory. Can be used multiple times. Will ignore all folders with name <NAME>. Use absolute path to ignore one specific folder.", action='append', required=False)
    parser.add_argument("-v", "--verbosity", action="count", default=0,help="Increase output verbosity", required=False)
    parser.add_argument("-o", "--outfile" , metavar='<OUTFILE>', default="md5hashes.txt.gz", help="Outputfile for hashlist" , required=False)
    parser.add_argument("-t", "--text" , action='store_true', help="Disable compression for outfile")
    parser.add_argument("-np", "--no-progress" , dest="progress", action='store_false', help="Show progressbar")
    parser.add_argument("-c", "--hash-algo" , action='append', help="Select Hashingalgorithm to use. Must be one of:\n{}".format(str(hashlib.algorithms_available)))
    parser.add_argument("-b", "--basepath" , default=os.path.sep , help="Basepath for hashing")
    global args
    args = parser.parse_args()

    args.magic='magic' in sys.modules
    if args.hash_algo:
        for h in args.hash_algo:
            if h not in hashlib.algorithms_available:
                print("Hashingalgorithm '{}' is not supported".format(h))
                exit(1)
    else:
        args.hash_algo=['md5']



    log(str(args))

    if args.text:
        outfile=open(args.outfile, 'wt')
    else:
        outfile=gzip.open(args.outfile, 'wt')

    # remote trailing slashes from excluded folder names
    if args.ignore_dir:
        args.ignore_dir=[x.rstrip(os.path.sep) for x in args.ignore_dir]
    #build filelist
    fl,ef=get_filelist(args.basepath)
    files=[]
    for f in tqdm(fl,desc="Hashing...",unit=' files',disable=not args.progress,mininterval=1):
        outfile.write(str(File(f,args.hash_algo))+"\n")


if __name__ == '__main__':
    main()
