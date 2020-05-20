#!/usr/bin/env python3

import os
import hashlib
import gzip
import argparse
import sys
import platform
import re
import logging
import json
import stat

try:
    import lief
except:
    pass

try:
    import magic
except:
    pass

try:
    from tqdm import tqdm
except:
    pass


class File:
    def __init__(self, file: str, hashtypes=None):
        if hashtypes is None:
            self.hashtypes = ['md5']
        else:
            self.hashtypes = hashtypes

        self.file = file
        self.filename = os.path.basename(self.file)
        self.results = {}
        self.errors = []
        self.filesize = -1
        self.stat = None

        if self.is_accessible():
            self.stat=self.get_stat()
            if not self.is_fifo():
                magic=self.get_magic()
                self.results.update(magic)
                if self.is_file():
                    self.filesize = self.get_size()
                    if self.filesize >= 0 and ((self.filesize < args.max_file_size) or (args.max_file_size <= 0)):
                        self.results.update(self.get_hashes())
                        if 'file_mime' in magic:
                            if "application/x-dosexec" in magic["file_mime"] or "application/octet-stream" in magic["file_mime"]:
                                self.results.update(self.get_signer())
                                # self.resulls.update(self.get_imphash())

    def is_accessible(self):
        try:
            return os.access(self.file, os.R_OK)
        except OSError as e:
            self.errors.append("FileAccessError[{}]".format(e.strerror))
            return False

    def is_fifo(self):
        try:
            return stat.S_ISFIFO(self.get_stat().st_mode)
        except OSError as e:
            self.errors.append("FileFIFOError[{}]".format(e.strerror))
            return False

    def is_regular_file(self):
        try:
            return stat.S_ISREG(self.get_stat().st_mode)
        except OSError as e:
            self.errors.append("FileFIFOError[{}]".format(e.strerror))
            return False

    def get_stat(self):
        if self.stat is not None:
            return self.stat
        try:
            return os.stat(self.file)
        except OSError as e:
            self.errors.append("FileSTATError[{}]".format(e.strerror))
            return None

    def is_file(self):
        try:
            return os.path.isfile(self.file)
        except OSError as e:
            self.errors.append("FileCheckError[{}]".format(e.strerror))
            return False

    def get_size(self):
        try:
            size = os.path.getsize(self.file)
        except OSError as e:
            self.errors.append("FileSizeError[{}]".format(e.strerror))
            return -1
        return size

    def get_signer(self):
        if 'lief' in sys.modules:
            try:
                bin_obj=lief.parse(self.file)
                if bin_obj is not None and bin_obj.has_signature:
                    signer=bin_obj.signature.signer_info.issuer
                    result = {
                        "signer": signer[0],
                        "signer_serial": ''.join(format(x, '02x') for x in signer[1])
                    }
                    return result
            except OSError as e:
                self.errors.append("LiefError[{}]".format(e.strerror))
            except Exception as e:
                self.errors.append("LiefError[{}]".format(str(e)))
        return {}

    def get_magic(self):
        if 'magic' in sys.modules:
            try:
                result = {
                    "file_type": magic.from_file(self.file),
                    "file_mime": magic.from_file(self.file, mime=True)
                }
                return result
            except OSError as e:
                self.errors.append("MagicError[{}]".format(e.strerror))
            except magic.MagicException as e:
                self.errors.append("MagicError[{}]".format(str(e)))
        return {}

    def __str__(self):
        result = {"file_name": self.file, "file_size": self.filesize, "results": self.results, "errors": self.errors}
        return json.dumps(result)

    def get_hashes(self):
        hashers = [hashlib.new(hashtype) for hashtype in self.hashtypes]
        hpb = None
        if args.progress and args.verbosity > 0:
            hpb = mtqdm(total=self.filesize, desc=self.filename, unit='byte', leave=False)
        try:
            with open(self.file, 'rb') as f:
                data = f.read(65536)
                while len(data) > 0:
                    if hpb is not None:
                        hpb.update(len(data))
                    for hasher in hashers:
                        hasher.update(data)
                    data = f.read(65536)
        except OSError as e:
            self.errors.append("FileHashError[{}]".format(e.strerror))
            return {}
        if hpb is not None:
            hpb.close()
        result = {}
        for hasher in hashers:
            result[hasher.name] = hasher.hexdigest()
        return result


def mtqdm(*args, **kwargs):
    ascii_only = True if platform.system() == 'Windows' else False
    if 'mininterval' not in kwargs:
        kwargs["mininterval"] = 1
    if 'ascii' not in kwargs:
        kwargs['ascii'] = ascii_only
    if 'dynamic_ncols' not in kwargs:
        kwargs['dynamic_ncols'] = True
    return tqdm(*args, **kwargs)


def setup_logging():
    # Create logger with max verbosity
    global log
    log = logging.getLogger("filehasher")
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s:%(levelname)s: %(message)s')
    # formatter = log.Formatter(log.BASIC_FORMAT)

    console_log = logging.StreamHandler()
    console_log.setFormatter(formatter)
    console_log.setLevel(logging.ERROR)

    file_log = logging.FileHandler(get_hostname() + ".log")
    file_log.setFormatter(formatter)
    file_log.setLevel(logging.INFO)

    log.addHandler(file_log)
    log.addHandler(console_log)
    log.info("Logging started...")


def fileerror(exception):
    log.warning("{} : Couldn't walk path [{}]".format(exception.filename, exception.strerror))


def get_hostname():
    pat = re.compile('[^a-zA-Z0-9_-]+')
    return pat.sub("_", platform.node().lower().strip())


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
                fullpath = os.path.join(path, subfolder)
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
    parser.add_argument("-np", "--no-progress", dest="progress", action='store_false', help="Do not show progressbar")
    parser.add_argument("-c", "--hash-algo", action='append',
                        help="Select Hashingalgorithm to use. Must be one of:\n{}".format(
                            str(hashlib.algorithms_available)))
    parser.add_argument("-b", "--basepath", default=os.path.sep, help="Basepath for hashing")
    global args

    setup_logging()

    args = parser.parse_args()
    # process arguments

    # if tqdm is not installed disable progressbars
    if 'tqdm' not in sys.modules: args.progress = False
    args.magic = 'magic' in sys.modules

    # if specified hashalgos are not supported exit with error
    if args.hash_algo:
        for h in args.hash_algo:
            if h not in hashlib.algorithms_available:
                print("Hashingalgorithm '{}' is not supported".format(h))
                exit(1)
    else:
        args.hash_algo = ['md5', 'sha256']

    if not args.outfile:
        args.outfile = "{}_hashlist.txt".format(get_hostname())

    if args.text:
        outfile = open(args.outfile, 'wt')
    else:
        outfile = gzip.open(args.outfile + ".gz", 'wt')

    # remote trailing slashes from excluded folder names
    if args.ignore_dir:
        args.ignore_dir = [x.rstrip(os.path.sep) for x in args.ignore_dir]
    if platform.system() == 'Linux':
        args.ignore_dir = ['/proc', '/sys'] if args.ignore_dir is None else args.ignore_dir + ['/proc', '/sys']

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
