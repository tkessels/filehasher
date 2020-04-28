#!/usr/bin/env python3

import os
import hashlib
import gzip
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-m", "--max-file-size", help="Max Size of files to hash in bytes", type=int, default=(10*1024*1024), required=False)
parser.add_argument("-d", "--ignore-dir", help="Ignore directory", action='append', required=False)
parser.add_argument("-v", "--verbosity", action="count", default=0,help="increase output verbosity", required=False)

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
                    hash=hashlib.md5(data.read()).hexdigest()
            else:
                log("skipping file {} because of size. ({})".format(file,os.path.getsize(file)))

    except OSError as e:
        log("could not access file {} [{}]".format(file,str(type(e))),0)
    return hash


with gzip.open('./md5hashes.txt.gz', 'wt') as outfile:
    for path,folders,files in os.walk('/',topdown=True):
        log("processing path {}".format(path))
        log("following folders were found: {}".format(str(folders)),3)

        # remove ignored foldersfrom traversal list
        if args.ignore_dir:
            # skip if path is in ignore list
            if path in args.ignore_dir:
                folders[:] = []
                files[:] = []
            # remove subfolders if subfoldernames are in ignorelist
            excluded_folders=[x for x in folders if x in args.ignore_dir]
            log("following folders will be excluded: {}".format(str(excluded_folders)),1)
            for x in excluded_folders : folders.remove(x)

        for file in [os.path.join(path,f) for f in files]:
            log("processing file {}".format(file))
            hash=get_file_hash(file)
            if hash:
                output="{}  {}\n".format(hash,file)
                log(output,1)
                outfile.write(output)
