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
import datetime

try:
    import yara
except ModuleNotFoundError:
    pass

try:
    import lief
except ModuleNotFoundError:
    pass

try:
    import magic
except ModuleNotFoundError:
    pass

try:
    from tqdm import tqdm
except ModuleNotFoundError:
    pass

try:
    import ssdeep
except ModuleNotFoundError:
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
        self.hashes = {}
        self.errors = []
        self.filesize = -1
        self.stat = self.get_stat()
        if self.is_accessible():
            if self.is_fifo() is None or self.is_fifo():
                self.errors.append("FileIsPipeError")
            else:
                self.results.update(self.get_magic())
                if self.is_file():
                    self.filesize = self.get_size()
                    if self.filesize >= 0:
                        if (self.filesize < args.max_file_size) or (args.max_file_size <= 0):
                            self.hashes.update(self.get_hashes())
                            self.hashes.update(self.get_ssdeep())
                            self.results.update(self.get_signer())
                            self.results.update(self.scan_yara())
                        else:
                            self.errors.append("FileTooBigError")

    def is_accessible(self):
        try:
            return os.access(self.file, os.R_OK)
        except OSError as e:
            self.errors.append(f"FileAccessError[{e.strerror}]")
            return False

    def is_fifo(self):
        try:
            if self.stat is not None:
                return stat.S_ISFIFO(self.stat.st_mode)
        except OSError as e:
            self.errors.append(f"FileFIFOError[{e.strerror}]")
        return None

    def get_timestamps(self):
        if self.stat is not None:
            try:
                result = {
                    'ctime': f"{datetime.datetime.fromtimestamp(self.stat.st_ctime)}",
                    'mtime': f"{datetime.datetime.fromtimestamp(self.stat.st_mtime)}",
                    'atime': f"{datetime.datetime.fromtimestamp(self.stat.st_atime)}"
                }
                return result
            except OSError:
                pass
            except OverflowError:
                pass
        return {}

    def get_inode(self):
        if self.stat is not None:
            return self.stat.st_ino
        return -1

    def get_stat(self):
        try:
            return os.stat(self.file)
        except OSError as e:
            self.errors.append(f"FileSTATError[{e.strerror}]")
            return None

    def is_file(self):
        try:
            return os.path.isfile(self.file)
        except OSError as e:
            self.errors.append(f"FileCheckError[{e.strerror}]")
            return False

    def get_size(self):
        try:
            size = os.path.getsize(self.file)
        except OSError as e:
            self.errors.append(f"FileSizeError[{e.strerror}]")
            return -1
        return size

    def scan_yara(self):
        result = {}
        if args.yara and args.yararules:
            try:
                with open(self.file, 'rb') as f:
                    matches = args.yararules.match(data=f.read())
                if len(matches) > 0:
                    tags = set()
                    for m in matches:
                        for tag in m.tags:
                            tags.add(tag)
                    result['tags'] = ",".join(list(tags))
                    result['rules'] = ",".join([m.rule for m in matches])
            except yara.TimeoutError:
                self.errors.append('YaraTimeoutError')
                pass
            except yara.Error as e:
                self.errors.append(f'YaraError[{e}]')
                pass
        return result

    def get_signer(self):
        if args.lief:
            try:
                if lief.is_pe(self.file):
                    bin_obj = lief.parse(self.file)
                    if bin_obj is not None and bin_obj.has_signatures:
                        result = {
                            "signature_validation": bin_obj.verify_signature().name()
                        }
                        for idx, signature in enumerate(bin_obj.signatures):
                            certs = [c for c in signature.certificates]
                            chain = [certs[0].issuer] + [cert.subject for cert in certs]
                            chain_serial = [''.join(format(x, '02x') for x in cert.serial_number) for cert in signature.certificates]
                            result[f"signature_{idx}_chain"] = ' > '.join(chain)
                            result[f"signature_{idx}_serials"] = ' > '.join(chain_serial)
                        return result
            except OSError as e:
                self.errors.append(f"LiefError[{e.strerror}]")
            except Exception as e:
                self.errors.append(f"LiefError[{str(e)}]")
        return {}

    def get_magic(self):
        if args.magic and 'magic' in sys.modules:
            try:
                result = {
                    "file_type": magic.from_file(self.file),
                    "file_mime": magic.from_file(self.file, mime=True)
                }
                return result
            except OSError as e:
                self.errors.append(f"MagicOSError[{e.strerror}]")
            except magic.MagicException as e:
                self.errors.append("MagicError")
        return {}

    def get_ssdeep(self):
        if args.ssdeep and 'ssdeep' in sys.modules:
            try:
                result = {
                    "ssdeep": ssdeep.hash_from_file(self.file)
                }
                return result
            except IOError as e:
                self.errors.append(f"SSDeepIOError[{e.strerror}]")
            except ssdeep.InternalError as e:
                self.errors.append(f"SSDeepError[{e}]")
        return {}

    def __str__(self):
        result = {
            "file_name": self.file,
            "file_size": self.filesize,
            "inode": self.get_inode(),
            "timestamps": self.get_timestamps(),
            "hashes": self.hashes,
            "results": self.results,
            "errors": self.errors
        }
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
            self.errors.append(f"FileHashError[{e.strerror}]")
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
    log = logging.getLogger("filehasher")
    # Create logger with max verbosity for logfile logging
    logging.basicConfig(filename=args.outfile + ".log",level=logging.INFO,format='%(asctime)s:%(levelname)s: %(message)s')
    formatter = logging.Formatter('%(asctime)s:%(levelname)s: %(message)s')
    # Add Console Logging with lower Verbosity
    console_log = logging.StreamHandler()
    console_log.setFormatter(formatter)
    console_log.setLevel(logging.ERROR)
    log.addHandler(console_log)

    logging.info("Logging started...")
    #Turn of Lief - Lib - Logging messing up everything
    if args.lief:
        lief.logging.disable()


def fileerror(exception):
    logging.warning(f"{exception.filename} : Couldn't walk path [{exception.strerror}]")


def get_hostname():
    pat = re.compile('[^a-zA-Z0-9_-]+')
    return pat.sub("_", platform.node().lower().strip())


def get_filelist(basepath):
    fpb = mtqdm(desc="Dicovering Files", unit=' file') if args.progress else None
    filelist = []
    excludedfolders = []
    for path, folders, files in os.walk(basepath, onerror=fileerror, topdown=True):
        logging.debug(f"processing path {path}")
        logging.debug(f"following folders were found: {str(folders)}")

        # remove ignored foldersfrom traversal list
        if args.ignore_dir:
            # skip if path is in ignore list
            if path in args.ignore_dir:
                logging.info(f"{path} will be ignored")
                excludedfolders.append(path)
                folders.clear()
                files.clear()

            # remove subfolders if subfoldernames are in ignorelist
            excluded_subfolders = [x for x in folders if x in args.ignore_dir]
            for subfolder in excluded_subfolders:
                folders.remove(subfolder)
                fullpath = os.path.join(path, subfolder)
                logging.info(f"{fullpath} will be ignored")
                excludedfolders.append(fullpath)

        if (fpb is not None) and (len(files) > 0): fpb.update(len(files))
        filelist.extend([os.path.join(path, f) for f in files])
    if fpb is not None: fpb.close()
    return filelist, excludedfolders


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--max-file-size", metavar='<SIZE>', type=int, default=(50 * 1024 * 1024), required=False,
                        help='Max Size of files to hash in bytes. Set value of <SIZE> <= 0 to disable filtering of '
                             'large files. This will increase the time required. Default value is 50M.')
    parser.add_argument("-d", "--ignore-dir", metavar='<NAME>', action='append', required=False,
                        help="Ignore directory. Can be used multiple times. Will ignore all folders with name <NAME>. "
                             "Use absolute path to ignore one specific folder.")
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="Increase output verbosity", required=False)
    parser.add_argument("-o", "--outfile", metavar='<OUTFILE>', help="Outputfile for hashlist", required=False)
    parser.add_argument("-y", "--yarafile", metavar='<YARAFILE>', help="Yara Rules to use", action='append', required=False)
    parser.add_argument("-t", "--text", action='store_true', help="Disable compression for outfile")
    parser.add_argument("-np", "--no-progress", dest="progress", action='store_false', help="Do not show progressbar")
    parser.add_argument("-nm", "--no-magic", dest="magic", action='store_false', help="Do not detect filetypes with libmagic")
    parser.add_argument("-ns", "--no-signer", dest="lief", action='store_false', help="Do not extract digital signatures from binaries")
    parser.add_argument("-ny", "--no-yara", dest="yara", action='store_false', help="Do not run yara scans")
    parser.add_argument("-nf", "--no-ssdeep", dest="ssdeep", action='store_false', help="Do not compute fuzzy hashes")
    parser.add_argument("-c", "--hash-algo", action='append', help=f"Select Hashingalgorithm to use. Must be one of:\n{str(hashlib.algorithms_available)}")
    parser.add_argument("-b", "--basepath", default=os.path.sep, help="Basepath for hashing")
    global args
    args = parser.parse_args()

    if not args.outfile:
        args.outfile = f"{get_hostname()}_hashlist.txt"

    setup_logging()

    # process feature switches from commandline

    # if tqdm is not installed disable progressbars
    if 'tqdm' not in sys.modules:
        args.progress = False
        logging.warning("module tqdm not installed")
        logging.warning("Progressbars disabled")

    if 'magic' not in sys.modules:
        args.magic = False
        logging.warning("module python-magic not installed")
        logging.warning("Filetype identification disabled")

    if 'ssdeep' not in sys.modules:
        args.ssdeep = False
        logging.warning("module ssdeep not installed")
        logging.warning("Fuzzy Hashing is disabled")

    if 'lief' not in sys.modules:
        args.lief = False
        logging.warning("module lief not installed")
        logging.warning("Signature extraction for binaries disabled")

    if 'yara' not in sys.modules:
        args.yara = False
        args.yararules = None
        logging.warning("module yara-python not installed")
        logging.warning("Files will not be scanned with yara")
    elif args.yara:
        logging.info("YARA enabled...")
        args.yararules = None
        if args.yarafile:
            rules = {}
            for idx, f in enumerate(args.yarafile):
                logging.info(f"Compiling specified rules {f}")
                try:
                    # test yara file
                    r = yara.compile(f)
                    basename = os.path.splitext(os.path.basename(f))
                    name = f"{idx}_{basename}"
                    # add it to rules dict with filename as namespace
                    rules[name] = f
                except yara.YaraSyntaxError as e:
                    logging.error(f"Syntax error in {f} [{e}]")
                    pass
            args.yararules = yara.compile(filepaths=rules)
        elif os.path.isfile(default_yarafile := os.path.join(os.getcwd(), "filehasher.yar")):
            logging.info(f"Found Rules {default_yarafile}")
            args.yararules = yara.compile(filepath=default_yarafile)

    # if specified hashalgos are not supported exit with error
    if args.hash_algo:
        for h in args.hash_algo:
            if h not in hashlib.algorithms_available:
                print(f"Hashingalgorithm '{h}' is not supported")
                exit(1)
    else:
        args.hash_algo = ['md5', 'sha256']

    if args.text:
        outfile = open(args.outfile, 'wt')
    else:
        outfile = gzip.open(args.outfile + ".gz", 'wt')

    # remove trailing slashes from excluded folder names
    if args.ignore_dir:
        args.ignore_dir = [x.rstrip(os.path.sep) for x in args.ignore_dir]
    if platform.system() == 'Linux':
        args.ignore_dir = ['/proc', '/sys'] if args.ignore_dir is None else args.ignore_dir + ['/proc', '/sys']

    logging.info(str(args))
    logging.info(platform.platform())
    logging.info("Filelist Creation started")
    fl, ef = get_filelist(args.basepath)
    logging.info("Filelist Creation completed")
    logging.info("File Hashing started")
    if args.progress: fl = mtqdm(fl, desc="Hashing", unit='file')
    try:
        filecount = 0
        for f in fl:
            try:
                outfile.write(str(File(f, args.hash_algo)) + "\n")
                filecount += 1
            except Exception as e:
                logging.error(f"Unexpected Error [{str(e)}] while Processing File. [{f}]")
        logging.info("File Hashing completed")
    finally:
        outfile.close()
    logging.info("Analyzed {}/{} files.".format(filecount, len(fl)))
    with open(outfile.name, 'rb') as hashlistfile:
        hasher = hashlib.md5()
        hasher.update(hashlistfile.read())
    logging.info(hasher.hexdigest())
    logging.info("Done")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Keyboard Interrupt detected: Exiting")
