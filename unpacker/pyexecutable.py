"""
Code reference from https://github.com/countercept/python-exe-unpacker/blob/master/python_exe_unpack.py
"""
import abc
import logging
import os
import pefile
import sys
import uncompyle6

logger = logging.getLogger(__name__)

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
            logger.error("Not an executable")
            sys.exit(1)
        except FileNotFoundException:
            logger.error("No such file `{}`".format(self.file_path))
            sys.exit(1)
        except Exception as e:
            logger.error("Exception `{}`".format(e))
            logger.error("Could not open {}".format(self.file_path))
            sys.exit(1)       


    def close(self):
        try:
            self.fPtr.close()
        except:
            pass


    @staticmethod
    def decompile_pyc(dir_decompiled, pyc_files, output_file=None):
        return uncompyle6.main.main(dir_decompiled, dir_decompiled, pyc_files, [], output_file)
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
