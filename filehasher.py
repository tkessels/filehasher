import os
import hashlib
import gzip
import stat




def get_file_hash(file):
    try:
        with open(file,'rb') as data:
            return hashlib.md5(data.read()).hexdigest()
    except Exception:
        print("could not hash file {}".format(file))
        return None


walker=os.walk('/')
with gzip.open('./md5hashes.txt.gz', 'wt') as outfile:
    for path,folders,files in walker:
        for file in [os.path.join(path,f) for f in files]:
            if (os.path.isfile(file) and os.access(file,os.R_OK) ):
                hash=get_file_hash(file)
                if hash:
                    output="{}  {}\n".format(hash,file)
                    outfile.write(output)
