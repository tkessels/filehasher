#!/usr/bin/env python3

import os
import hashlib
import gzip
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-m", "--max-file-size", help="Max Size of files to hash in bytes", type=int, default=(10*1024*1024), required=False)
parser.add_argument("-d", "--ignore-dir", help="Ignore directory", action='append', required=False)
parser.add_argument("-v", "--verbosity", action="count", default=0,help="Increase output verbosity", required=False)
parser.add_argument("-o", "--outfile" , default="md5hashes.txt.gz", help="Outputfile for hashlist" , required=False)
parser.add_argument("-t", "--text" , action='store_true', help="Disable compression for outfile")
parser.add_argument("-c", "--hash-algo" , default='md5', help="Select Hashingalgorithm to use. Must be one of:\n{}".format(str(hashlib.algorithms_available)))



args = parser.parse_args()
def log(message,loglevel=2):
    level=["error","info","debug","trace"]
    if loglevel < args.verbosity:
        print("[{}] : {}".format(level[loglevel],message.rstrip()))

def get_file_hash(file):
    hash=None
    try:
        if os.path.isfile(file) and os.access(file,os.R_OK):
            if os.path.getsize(file)<args.max_file_size:
                with open(file,'rb') as data:
                    hasher=hashlib.new(args.hash_algo)
                    hasher.update(data.read())
                    hash=hasher.hexdigest()
            else:
                log("skipping file {} because of size. ({})".format(file,os.path.getsize(file)))

    except OSError as e:
        log("could not access file {} [{}]".format(file,str(type(e))),0)
    return hash

log(str(args))
if args.text:
    outfile=open(args.outfile, 'wt')
else:
    outfile=gzip.open(args.outfile, 'wt')

for path,folders,files in os.walk(os.path.sep,topdown=True):
    log("processing path {}".format(path),3)
    log("following folders were found: {}".format(str(folders)),3)

    # remove ignored foldersfrom traversal list
    if args.ignore_dir:
        # skip if path is in ignore list
        if path in args.ignore_dir:
            folders[:] = []
            files[:] = []
        # remove subfolders if subfoldernames are in ignorelist
        excluded_folders=[x for x in folders if x in args.ignore_dir]
        log("following folders will be excluded: {}".format(str(excluded_folders)),2)
        for x in excluded_folders : folders.remove(x)

    for file in [os.path.join(path,f) for f in files]:
        log("processing file {}".format(file),3)
        hash=get_file_hash(file)
        if hash:
            output="{}  {}\n".format(hash,file)
            log(output,1)
            outfile.write(output)
