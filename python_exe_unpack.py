#!/usr/bin/python
'''
Author: In Ming Loh
Email: inming.loh@countercept.com
'''
from __future__ import print_function
import pefile
import sys
import os
import abc
import argparse
import glob
import shutil
from xdis.load import load_module


DEV_NULL = open(os.devnull, "wb")
UNPACKED_FOLDER_NAME = "unpacked"

logging = True
print_or = print


def print(str):
    global logging
    if logging:
        print_or(str)


class python_exe_unpackError(Exception):
    def __init__(self, message):
        self.message = "python_exe_unpackError " + message
        return super().__init__(self.message)


class FileNotFoundException(Exception):
    def __init__(self):
        self.message = "python_exe_unpackError " + \
            "Raised when binary is not found"
        return super().__init__(self.message)


class FileFormatException(Exception):
    def __init__(self):
        self.message = "python_exe_unpackError " + \
            "Raised when the binary is not exe or dll"
        return super().__init__(self.message)


class PythonExectable(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, path, output_dir=None):
        self.file_path = path

        # Check if the folder to store unpacked and decompiled code exist. Else, create it.
        if output_dir is None:
            self.extraction_dir = os.path.join(
                os.getcwd(), UNPACKED_FOLDER_NAME, os.path.basename(self.file_path))
        else:
            self.extraction_dir = os.path.join(
                output_dir, os.path.basename(self.file_path))

        if not os.path.exists(self.extraction_dir):
            os.makedirs(self.extraction_dir)
        else:
            shutil.rmtree(self.extraction_dir, ignore_errors=True)

        self.with_header_pycs_dir = os.path.join(
            self.extraction_dir, "with_header_pycs")
        if not os.path.exists(self.with_header_pycs_dir):
            os.makedirs(self.with_header_pycs_dir)

        self.py_sources_dir = os.path.join(self.extraction_dir, "sources")
        if not os.path.exists(self.py_sources_dir):
            os.makedirs(self.py_sources_dir)

    def open_executable(self):
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundException

            pe_file = pefile.PE(self.file_path)
            if not (pe_file.is_dll() or pe_file.is_exe()):
                raise FileFormatException

            self.fPtr = open(self.file_path, 'rb')
            self.fileSize = os.stat(self.file_path).st_size
        except FileFormatException:
            raise python_exe_unpackError("Not an executable")

        except FileNotFoundException:
            raise python_exe_unpackError("File not found")
        except Exception as e:
            raise e

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    @staticmethod
    def get_code_obj(dir_compiled, dir_decompiled, pyc_files, output_file=None):
        code_obj = {}
        try:
            code_obj = load_module(os.path.join(
                dir_compiled, pyc_files[0]), {})[3]
        except Exception as e:
            raise e
        return code_obj

    @ staticmethod
    def current_dir_pyc_files(pyc_directory):
        return [x for x in os.listdir(pyc_directory) if x.endswith(".pyc")]

    @ abc.abstractmethod
    def is_magic_recognised(self):
        """Function that check if the magic bytes is recognised by the python packer."""

    @ abc.abstractmethod
    def unpacked(self, filename):
        """Function that unpacked the binary to python."""


class PyInstaller(PythonExectable):
    '''
    EXE is created using CArchive instead of ZlibArchive:
    https://pyinstaller.readthedocs.io/en/latest/advanced-topics.html#carchive

    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+

    PyInstaller cookie format before version 2.0:
    /* The CArchive Cookie, from end of the archive. */
    typedef struct _cookie {
        char magic[8]; /* 'MEI\014\013\012\013\016' */
        int  len;      /* len of entire package */
        int  TOC;      /* pos (rel to start) of TableOfContents */
        int  TOClen;   /* length of TableOfContents */
        int  pyvers;   /* new in v4 */
    } COOKIE;

    PyInstaller cookie format after version 2.1:
    /* The CArchive Cookie, from end of the archive. */
    typedef struct _cookie {
        char magic[8];      /* 'MEI\014\013\012\013\016' */
        int  len;           /* len of entire package */
        int  TOC;           /* pos (rel to start) of TableOfContents */
        int  TOClen;        /* length of TableOfContents */
        int  pyvers;        /* new in v4 */
        char pylibname[64]; /* Filename of Python dynamic library e.g. python2.7.dll. */
    } COOKIE;
    '''

    def __init__(self, path, output_dir=None):
        super(PyInstaller, self).__init__(path, output_dir)

        self.entry_points = []
        self.py_ver = 0

        self.py_inst_archive = PyInstArchive(self.file_path)
        # A hack to check the existence of the file
        self.open_executable()
        self.close()

        self.py_inst_archive.open()

    def is_magic_recognised(self):
        return self.py_inst_archive.checkFile()

    def __is_encrypted(self, extracted_binary_path, encrypted_key_path_pyc):
        return os.path.exists(extracted_binary_path) and os.path.exists(encrypted_key_path_pyc)

    def __get_encryption_key(self, encrypted_key_path_pyc):
        code_obj = PythonExectable.get_code_obj(
            self.extraction_dir, self.extraction_dir, [encrypted_key_path_pyc], "temp_header.py")
        return code_obj.co_consts[0]

    def __decrypt_pyc(self, extracted_binary_path, encryption_key):
        # Code reference from https://0xec.blogspot.sg/2017/02/extracting-encrypted-pyinstaller.html
        from Crypto.Cipher import AES
        import zlib
        crypt_block_size = 16
        encrypted_pyc_folder = os.path.join(
            extracted_binary_path, "out00-PYZ.pyz_extracted")
        encrypted_pyc_list = glob.glob(
            encrypted_pyc_folder + '/*.pyc.encrypted')
        for file_name in encrypted_pyc_list:
            try:
                encrypted_pyc = os.path.join(encrypted_pyc_folder, file_name)
                encrypted_pyc_file = open(encrypted_pyc, 'rb')
                decrypted_pyc_file = open(
                    encrypted_pyc[:encrypted_pyc.rfind('.')], 'wb')
                initialization_vector = encrypted_pyc_file.read(
                    crypt_block_size)
                cipher = AES.new(encryption_key.encode(),
                                 AES.MODE_CFB, initialization_vector)
                plaintext = zlib.decompress(
                    cipher.decrypt(encrypted_pyc_file.read()))
                decrypted_pyc_file.write(plaintext)
                encrypted_pyc_file.close()
                decrypted_pyc_file.close()
            except Exception as e:
                raise python_exe_unpackError(
                    f"Exception occured during pyc decryption and decompiling\n{e}")

    # To deal with encrypted pyinstaller binary if it's encrypted

    def __decrypt(self):
        extracted_binary_path = self.extraction_dir
        encrypted_key_path_pyc = os.path.join(
            extracted_binary_path, "pyimod00_crypto_key.pyc")

        if self.__is_encrypted(extracted_binary_path, encrypted_key_path_pyc) == True:
            encryption_key = self.__get_encryption_key(encrypted_key_path_pyc)
            print("[*] AES key found: {0}".format(encryption_key))
            if encryption_key is not None:
                self.__decrypt_pyc(extracted_binary_path, encryption_key)
        # else:
        #   TO BE DONE

    def getPYCHeader(self):
        header = b''
        candidates_header_files = glob.glob(
            self.extraction_dir + '/pyimod0*.pyc')
        n_candidates = len(candidates_header_files)
        if n_candidates == 0:
            raise python_exe_unpackError(
                "No candidates files for extracting the PYC header")

        for n, candidate in enumerate(candidates_header_files):
            try:
                okay = PythonExectable.get_code_obj(
                    self.extraction_dir, self.extraction_dir, [candidate], "temp_header.py")
            except:
                continue

            if okay:
                with open(candidate, 'rb') as candidate_file:
                    header = candidate_file.read(4)
                    candidate_file.close()
                    break

            if n == n_candidates:
                raise python_exe_unpackError(
                    "No candidates files for extracting the PYC header is valid")
        if self.py_ver >= 37:               # PEP 552 -- Deterministic pycs
            header += b'\0' * 4        # Bitfield
            header += b'\0' * 8        # (Timestamp + size) || hash

        else:
            header += b'\0' * 4      # Timestamp
            if self.py_ver >= 33:
                header += b'\0' * 4  # Size parameter added in Python 3.3

        return header

    def __prepend_header_to_all_PYCs(self):
        PYCs_list = glob.glob(self.extraction_dir + '/*.pyc')
        PYCHeader = self.getPYCHeader()
        print(
            '[*] Prepending {0} header to {1} .pyc files:'.format(PYCHeader, len(PYCs_list)))
        for file_name in PYCs_list:
            rel_file_name = file_name[len(self.extraction_dir):]
            rel_file_dir = rel_file_name[:rel_file_name.rfind('/')]
            if not os.path.exists(self.with_header_pycs_dir + rel_file_dir):
                os.makedirs(self.with_header_pycs_dir + rel_file_dir)
            with open(file_name, 'rb') as pycNoHeaderFile, open(self.with_header_pycs_dir + rel_file_name, 'wb') as pycFile:
                first_fours = pycNoHeaderFile.read(4)
                if not (first_fours == PYCHeader[:4]):
                    pycFile.write(PYCHeader)
                else:
                    print("[*] Skipping prepend on {0}".format(rel_file_name))
                pycFile.write(first_fours)
                pycFile.write(pycNoHeaderFile.read())
                pycFile.close()
                pycNoHeaderFile.close()

    def __decompile_entry_PYCs(self):
        PYCs_list = []
        backup_PYCs = []
        for entry in self.entry_points:
            if not "pyi" in entry:
                PYCs_list.append(entry+".pyc")
            else:   # in case original script contains pyi in filename
                backup_PYCs.append(entry+".pyc")
        if len(PYCs_list) == 0:
            PYCs_list = backup_PYCs
        code_obj = PythonExectable.get_code_obj(
            self.with_header_pycs_dir, self.py_sources_dir, PYCs_list, self.py_inst_archive)
        return code_obj

    def __pyinstxtractor_extract(self):
        if self.py_inst_archive.getCArchiveInfo():
            self.py_inst_archive.parseTOC()
            (self.py_ver, self.entry_points) = self.py_inst_archive.extractFiles(
                self.extraction_dir)
            print('[*] Successfully extracted pyinstaller exe.')

    def unpacked(self, filename):
        print("[*] Unpacking the binary now")
        self.__pyinstxtractor_extract()
        self.__decrypt()
        self.__prepend_header_to_all_PYCs()
        return (self.__decompile_entry_PYCs(), self.py_ver)


PyInstArchive = None


def __handle(file_name, output_dir=None, log_enable=False, standalone=False):

    global PyInstArchive

    if standalone:
        from pyinstxtractor import PyInstArchive
    else:
        from PYExtr.pyinstxtractor import PyInstArchive

    global logging
    logging = log_enable
    pyinstaller = PyInstaller(file_name, output_dir)

    if pyinstaller.is_magic_recognised():
        print('[*] This exe is packed using pyinstaller')
        return pyinstaller.unpacked(file_name)
    else:
        print('[-] Sorry, can\'t tell what is this packed with')

    # Close all the open file
    pyinstaller.close()


if __name__ == '__main__':
    print("[*] On Python " + str(sys.version_info.major) +
          "." + str(sys.version_info.minor))
    parser = argparse.ArgumentParser(
        description="This program will detect, unpack and decompile binary that is packed in either py2exe or pyinstaller. (Use only one option)")
    parser.add_argument("-i", dest="input", required=False,
                        help="exe that is packed using py2exe or pyinstaller")
    parser.add_argument("-o", dest="output", required=False,
                        help="folder to store your unpacked and decompiled code. (Otherwise will default to current working directory and inside the folder\"unpacked\")")
    args = parser.parse_args()

    file_name = args.input
    output_dir = args.output

    if file_name is not None:
        __handle(file_name, output_dir)

    else:
        parser.print_help()
