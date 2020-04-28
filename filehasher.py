import os
import hashlib
import gzip
import stat
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--max-file-size", help="Max Size of files to hash in bytes", type=int, default=1073741824, required=False)
parser.add_argument("-v", "--verbosity", action="count", default=0,help="increase output verbosity", required=False)

args = parser.parse_args()

def log(message,loglevel=2):
    level=["error","info","debug"]
    if loglevel < args.verbosity:
        print("[{}] : {}".format(level[loglevel],message.rstrip()))

def get_file_hash(file):
    hash=None
    try:
        if os.path.isfile(file) and os.access(file,os.R_OK):
            if os.path.getsize(file)<args.max_file_size:
                with open(file,'rb') as data:
                    hash=hashlib.md5(data.read()).hexdigest()
    except Exception:
        log("could not access file {}".format(file),0)
    return hash


walker=os.walk('/')
with gzip.open('./md5hashes.txt.gz', 'wt') as outfile:
    for path,folders,files in walker:
        log("processing path {}".format(path),2)
        for file in [os.path.join(path,f) for f in files]:
            hash=get_file_hash(file)
            if hash:
                output="{}  {}\n".format(hash,file)
                log(output,1)
                outfile.write(output)
