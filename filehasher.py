#!/usr/bin/env python3

import os
import hashlib
import gzip
import argparse
import sys
import platform
import re
import logging

try:
    import magic
except:
    pass

try:
    from tqdm import tqdm
except:
    pass


class File:
    def __init__(self, filename: str, hashtypes=None):
        if hashtypes is None:
            hashtypes = ['md5']
        self.filename = filename
        self.file = os.path.basename(filename)
        self.filesize = -1
        self.results = {}
        self.filetype = ""
        self.errors = []
        if os.path.isfile(filename):
            if os.access(filename, os.R_OK):
                self.filesize = os.path.getsize(filename)
                if self.filesize >= 0 and ((self.filesize < args.max_file_size) or (args.max_file_size <= 0)):
                    hashers = [hashlib.new(hashtype) for hashtype in hashtypes]
                    hpb = None
                    if args.progress and args.verbosity > 0:
                        hpb = mtqdm(total=self.filesize, desc=self.file, unit='byte', leave=False)
                    try:
                        if args.magic:
                            self.filetype = magic.from_file(self.filename, mime=True)
                        with open(filename, 'rb') as f:
                            while True:
                                data = f.read(65536)
                                if hpb is not None: hpb.update(len(data))

                                if not data:
                                    break
                                else:
                                    for hasher in hashers:
                                        hasher.update(data)
                    except Exception as e:
                        self.errors.append("File could not be read")
                        print(e)
                    self.results = {h.name: h.hexdigest() for h in hashers}
                    if hpb is not None: hpb.close()
                else:
                    self.errors.append("File too big")
            else:
                self.errors.append("Can't read file")
        else:
            self.errors.append("Not a regular file")

    def __str__(self):
        return "{};{};{};{};{}".format(self.filename, self.filesize, self.filetype, str(self.results), str(self.errors))


def mtqdm(*args, **kwargs):
    ascii_only = True if platform.system() == 'Windows' else False
    if 'mininterval' not in kwargs: kwargs["mininterval"] = 1
    if 'ascii' not in kwargs: kwargs['ascii'] = ascii_only
    return tqdm(*args, **kwargs)


def setup_logging():
    #Create logger with max verbosity
    global log
    log=logging.getLogger("filehasher")
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s:%(levelname)s: %(message)s')
    # formatter = log.Formatter(log.BASIC_FORMAT)

    console_log = logging.StreamHandler()
    console_log.setFormatter(formatter)
    console_log.setLevel(logging.ERROR)

    file_log = logging.FileHandler(get_hostname()+".log")
    file_log.setFormatter(formatter)
    file_log.setLevel(logging.INFO)


    log.addHandler(file_log)
    log.addHandler(console_log)
    log.info("Logging started...")



def fileerror(exception):
    log.warning("{} : Couldn't walk path [{}]".format(exception.filename, exception.strerror))

def get_hostname():
    pat=re.compile('[^a-zA-Z0-9_-]+')
    return pat.sub("_",platform.node().lower().strip())

def get_filelist(basepath):
    fpb = mtqdm(desc="Dicovering Files", unit=' file') if args.progress else None
    filelist = []
    excludedfolders = []
    for path, folders, files in os.walk(basepath, onerror=fileerror, topdown=True):
        log.debug("processing path {}".format(path))
        log.debug("following folders were found: {}".format(str(folders)))

        # remove ignored foldersfrom traversal list
        if args.ignore_dir:
            # skip if path is in ignore list
            if path in args.ignore_dir:
                log.info("{} will be ignored".format(path))
                excludedfolders.append(path)
                folders.clear()
                files.clear()

            # remove subfolders if subfoldernames are in ignorelist
            excluded_subfolders = [x for x in folders if x in args.ignore_dir]
            for subfolder in excluded_subfolders:
                folders.remove(subfolder)
                fullpath=os.path.join(path, subfolder)
                log.info("{} will be ignored".format(fullpath))
                excludedfolders.append(fullpath)

        if (fpb is not None) and (len(files) > 0): fpb.update(len(files))
        filelist.extend([os.path.join(path, f) for f in files])
    if fpb is not None: fpb.close()
    return filelist, excludedfolders


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--max-file-size", metavar='<SIZE>',
                        help='Max Size of files to hash in bytes. Set value of <SIZE> <= 0 to disable filtering of '
                             'large files. This will increase the time required. Default value is 50M.',
                        type=int, default=(50 * 1024 * 1024), required=False)
    parser.add_argument("-d", "--ignore-dir", metavar='<NAME>',
                        help="Ignore directory. Can be used multiple times. Will ignore all folders with name <NAME>. "
                             "Use absolute path to ignore one specific folder.",
                        action='append', required=False)
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="Increase output verbosity",
                        required=False)
    parser.add_argument("-o", "--outfile", metavar='<OUTFILE>',
                        help="Outputfile for hashlist", required=False)
    parser.add_argument("-t", "--text", action='store_true', help="Disable compression for outfile")
    parser.add_argument("-np", "--no-progress", dest="progress", action='store_false', help="Show progressbar")
    parser.add_argument("-c", "--hash-algo", action='append',
                        help="Select Hashingalgorithm to use. Must be one of:\n{}".format(
                            str(hashlib.algorithms_available)))
    parser.add_argument("-b", "--basepath", default=os.path.sep, help="Basepath for hashing")
    global args

    setup_logging()

    args = parser.parse_args()
    #process arguments

    #if tqdm is not installed disable progressbars
    if 'tqdm' not in sys.modules: args.progress = False
    args.magic = 'magic' in sys.modules

    #if specified hashalgos are not supported exit with error
    if args.hash_algo:
        for h in args.hash_algo:
            if h not in hashlib.algorithms_available:
                print("Hashingalgorithm '{}' is not supported".format(h))
                exit(1)
    else:
        args.hash_algo = ['md5', 'sha256']

    if not args.outfile:
        args.outfile="{}_hashlist.txt".format(get_hostname())

    if args.text:
        outfile = open(args.outfile, 'wt')
    else:
        outfile = gzip.open(args.outfile+".gz", 'wt')

    # remote trailing slashes from excluded folder names
    if args.ignore_dir:
        args.ignore_dir = [x.rstrip(os.path.sep) for x in args.ignore_dir]
    if platform.system() == 'Linux':
        args.ignore_dir=['/proc','/sys'] if args.ignore_dir is None else args.ignore_dir + ['/proc','/sys']

    log.info(str(args))
    log.info(platform.platform())
    log.info(platform.release())

    # build filelist
    fl, ef = get_filelist(args.basepath)
    if args.progress: fl = mtqdm(fl, desc="Hashing", unit='file')
    try:
        for f in fl:
            outfile.write(str(File(f, args.hash_algo)) + "\n")
    except KeyboardInterrupt:
        outfile.close()

    log.info("Done")


if __name__ == '__main__':
    main()
