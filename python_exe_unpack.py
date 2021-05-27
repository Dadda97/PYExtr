#!/usr/bin/python
'''
Author: In Ming Loh
Email: inming.loh@countercept.com
'''
from __future__ import print_function
from shutil import copyfile
import sys
import os
import struct
import abc
import argparse
import glob
import shutil

import pefile
import pyinstxtractor
import uncompyle6
from unpy2exe import unpy2exe

DEV_NULL = open(os.devnull, "wb")
UNPACKED_FOLDER_NAME = "unpacked"

def user_input(message):
    if sys.version[0] == "3":
        return input(message)
    else:
        return raw_input(message)


class FileNotFoundException(Exception):
    """Raised when binary is not found"""
    pass

class FileFormatException(Exception):
    """Raised when the binary is not exe or dll"""
    pass

class PythonExectable(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, path, output_dir=None):
        self.file_path = path
        
        # Check if the folder to store unpacked and decompiled code exist. Else, create it.
        if output_dir is None:
            self.extraction_dir = os.path.join(os.getcwd(), UNPACKED_FOLDER_NAME, os.path.basename(self.file_path))
        else:
            self.extraction_dir = os.path.join(output_dir, os.path.basename(self.file_path))
        
        if not os.path.exists(self.extraction_dir):
            os.makedirs(self.extraction_dir)
        else:
            shutil.rmtree(self.extraction_dir, ignore_errors=True)
        
        self.with_header_pycs_dir = os.path.join(self.extraction_dir, "with_header_pycs")
        if not os.path.exists(self.with_header_pycs_dir):
           os.makedirs(self.with_header_pycs_dir)

        self.py_sources_dir = os.path.join(os.path.dirname(self.file_path), "sources", os.path.basename(self.file_path))
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
            print("[-] Not an executable")
            sys.exit(1)
        except FileNotFoundException:
            print("[-] No such file")
            sys.exit(1)
        except:
            print("[-] Error: Could not open {0}".format(self.file_path))
            sys.exit(1)       


    def close(self):
        try:
            self.fPtr.close()
        except:
            pass


    @staticmethod
    def decompile_pyc(dir_compiled, dir_decompiled, pyc_files, output_file=None):
        return uncompyle6.main.main(dir_compiled, dir_decompiled, pyc_files, [], output_file)
        # uncompyle6.main.main(dir_decompiled, dir_decompiled, pyc_files, None, None, None, False, False, False, False, False)


    @staticmethod
    def current_dir_pyc_files(pyc_directory):
        return [x for x in os.listdir(pyc_directory) if x.endswith(".pyc")]


    @abc.abstractmethod
    def is_magic_recognised(self):
        """Function that check if the magic bytes is recognised by the python packer."""


    @abc.abstractmethod
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
        
        self.py_inst_archive = pyinstxtractor.PyInstArchive(self.file_path)
        
        # A hack to check the existence of the file
        self.open_executable()
        self.close()

        self.py_inst_archive.open()


    def is_magic_recognised(self):
        return self.py_inst_archive.checkFile()


    def __is_encrypted(self, extracted_binary_path, encrypted_key_path_pyc):
        if os.path.exists(extracted_binary_path) and os.path.exists(encrypted_key_path_pyc):
            is_decrypt = user_input("[*] Encrypted pyc file is found. Decrypt it? [y/n]")
            if is_decrypt.lower() == "y":
                return True
            else:
                print("[!] Not implemented yet") #TO BE DONE
                sys.exit()
                
        return False


    def __get_encryption_key(self, encrypted_key_path_pyc):
        try:
            print("[*] Taking decryption key from {0}".format(encrypted_key_path_pyc))
            if os.path.exists(encrypted_key_path_pyc):
                encrypted_key_path_py = encrypted_key_path_pyc[:-4] + ".py"
                (total, okay, failed, verify_failed) = PythonExectable.decompile_pyc(self.extraction_dir,self.extraction_dir, [encrypted_key_path_pyc], encrypted_key_path_py)
                print("[*] Looking for key inside the .pyc...")
                if failed == 0 and verify_failed == 0:
                    from configparser import ConfigParser
                    from io import StringIO
                    ini_str = StringIO(u"[secret]\n" + open(encrypted_key_path_py, 'r').read())
                    config = ConfigParser()
                    config.readfp(ini_str)
                    temp_key = config.get("secret", "key")
                    # To remove single quote from first and last position in the extracted password
                    encryption_key = temp_key[1:len(temp_key)-1]
                    return encryption_key
            return None
        except Exception as e:
            print("[-] Exception occured while trying to get the encryption key.")
            print("[-] Error message: {0}".format(e))
            sys.exit(1)
        finally:
            if os.path.exists(encrypted_key_path_py):
                os.remove(encrypted_key_path_py)


    def __decrypt_pyc(self, extracted_binary_path, encryption_key):
        # Code reference from https://0xec.blogspot.sg/2017/02/extracting-encrypted-pyinstaller.html
        from Crypto.Cipher import AES
        import zlib
        crypt_block_size = 16
        encrypted_pyc_folder = os.path.join(extracted_binary_path, "out00-PYZ.pyz_extracted")
        encrypted_pyc_list =  glob.glob(encrypted_pyc_folder + '/*.pyc.encrypted') 
        for file_name in encrypted_pyc_list:
            try:
                encrypted_pyc = os.path.join(encrypted_pyc_folder, file_name)
                encrypted_pyc_file = open(encrypted_pyc, 'rb')
                decrypted_pyc_file = open(encrypted_pyc[:encrypted_pyc.rfind('.')], 'wb')
                initialization_vector = encrypted_pyc_file.read(crypt_block_size)
                cipher = AES.new(encryption_key.encode(), AES.MODE_CFB, initialization_vector)
                plaintext = zlib.decompress(cipher.decrypt(encrypted_pyc_file.read()))
                decrypted_pyc_file.write(plaintext)
                encrypted_pyc_file.close()
                decrypted_pyc_file.close()
            except Exception as e:
                print("[-] Exception occured during pyc decryption and decompiling")
                print("[-] Error message: {0}".format(e))
                sys.exit(1)


    # To deal with encrypted pyinstaller binary if it's encrypted
    def __decrypt(self):
        extracted_binary_path = self.extraction_dir
        encrypted_key_path_pyc = os.path.join(extracted_binary_path, "pyimod00_crypto_key.pyc") 

        if self.__is_encrypted(extracted_binary_path, encrypted_key_path_pyc) == True:
            encryption_key = self.__get_encryption_key(encrypted_key_path_pyc)
            print("[*] AES key found: {0}".format(encryption_key) )
            if encryption_key is not None:
                self.__decrypt_pyc(extracted_binary_path, encryption_key)
        #else:
        #   TO BE DONE

    def getPYCHeader(self):
        header = b''
        candidates_header_files = glob.glob(self.extraction_dir + '/pyimod0*.pyc')
        print(self.extraction_dir)
        n_candidates = len(candidates_header_files)
        if n_candidates == 0:
            print("[!] No candidates files for extracting the PYC header")
            sys.exit(1)

        for n,candidate in enumerate(candidates_header_files):
            (total, okay, failed, verify_failed) = PythonExectable.decompile_pyc(self.extraction_dir,self.extraction_dir, [candidate], "temp_header.py")
            if okay:
                with open(candidate, 'rb') as candidate_file:
                    header = candidate_file.read(4)
                    candidate_file.close()
                    break
            if n == n_candidates:
                print("[!] No candidates files for extracting the PYC header is valid")
                sys.exit(1)

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
        print('[*] Prepending {0} header to {1} .pyc files:'.format(PYCHeader, len(PYCs_list)))
        for file_name in PYCs_list:
            rel_file_name = file_name[len(self.extraction_dir):]
            rel_file_dir = rel_file_name[:rel_file_name.rfind('/')]
            if not os.path.exists(self.with_header_pycs_dir + rel_file_dir):
                os.makedirs(self.with_header_pycs_dir + rel_file_dir)
            with open(file_name, 'rb') as pycNoHeaderFile, open(self.with_header_pycs_dir  + rel_file_name  , 'wb') as pycFile:
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
        PythonExectable.decompile_pyc(self.with_header_pycs_dir, self.py_sources_dir, PYCs_list)

    def __pyinstxtractor_extract(self):
        if self.py_inst_archive.getCArchiveInfo():
            self.py_inst_archive.parseTOC()
            (self.py_ver, self.entry_points) = self.py_inst_archive.extractFiles(self.extraction_dir)
            print('[*] Successfully extracted pyinstaller exe.')

    def unpacked(self, filename):
        print("[*] Unpacking the binary now")
        self.__pyinstxtractor_extract()
        self.__decrypt()
        self.__prepend_header_to_all_PYCs()
        self.__decompile_entry_PYCs()
        print("[+] Binary unpacked successfully")


class Py2Exe(PythonExectable):

    def is_magic_recognised(self):
        self.open_executable()
        is_py2exe = False
        script_resource = None
        pe_file = pefile.PE(self.file_path)

        if hasattr(pe_file,'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                if str(entry.name) == str("PYTHONSCRIPT"):
                    script_resource = entry.directory.entries[0].directory.entries[0]                
                    break
        
        if script_resource != None:
            rva = script_resource.data.struct.OffsetToData
            size = script_resource.data.struct.Size
            dump = pe_file.get_data(rva, size)
            current = struct.calcsize(b'iiii')
            metadata = struct.unpack(b'iiii', dump[:current])
            if hex(metadata[0]) == "0x78563412":
                is_py2exe = True

        self.close()
        return is_py2exe


    def unpacked(self, filename):
        print("[*] Unpacking the binary now")
        is_error = False
        try:
            unpy2exe(filename, None, self.extraction_dir)
        except:
            # python 2 and 3 marshal data differently and has different implementation and unfortunately unpy2exe depends on marshal.
            print("[-] Error in unpacking the exe. Probably due to version incompability (exe created using python 2 and run this script with python 3)")
            is_error = True

        if not is_error:
            folder_count = len(os.listdir(self.extraction_dir))
            if folder_count >= 1:
                PythonExectable.decompile_pyc(self.extraction_dir, self.extraction_dir, PythonExectable.current_dir_pyc_files(self.extraction_dir))
            else:
                print("[-] Error in unpacking the binary")
                sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="This program will detect, unpack and decompile binary that is packed in either py2exe or pyinstaller. (Use only one option)")
    parser.add_argument("-i", dest="input" ,required=False, help="exe that is packed using py2exe or pyinstaller")
    parser.add_argument("-o", dest="output" ,required=False, help="folder to store your unpacked and decompiled code. (Otherwise will default to current working directory and inside the folder\"unpacked\")")
    args = parser.parse_args()

    file_name = args.input
    output_dir = args.output

    if file_name is not None:
        pyinstaller = PyInstaller(file_name, output_dir)
        py2exe = Py2Exe(file_name, output_dir)

        if py2exe.is_magic_recognised():
            print('[*] This exe is packed using py2exe')
            py2exe.unpacked(file_name)
        elif pyinstaller.is_magic_recognised():
            print('[*] This exe is packed using pyinstaller')
            pyinstaller.unpacked(file_name)
        else:
            print('[-] Sorry, can\'t tell what is this packed with')

        # Close all the open file
        pyinstaller.close()
        py2exe.close()

    else:
        parser.print_help()
        

if __name__ == '__main__':
    print("[*] On Python " + str(sys.version_info.major) + "." + str(sys.version_info.minor))
    main()