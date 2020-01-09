import logging
import os
import pefile
from unpy2exe import unpy2exe
from unpacker.pyexecutable import PythonExectable

logger = logging.getLogger(__name__)

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
            if metadata[0] == 0x78563412:
                is_py2exe = True

        self.close()
        return is_py2exe


    def unpacked(self, filename):
        logger.info("Unpacking...")
        is_error = False
        try:
            unpy2exe(filename, None, self.extraction_dir)
        except:
            # python 2 and 3 marshal data differently and has different implementation and unfortunately unpy2exe depends on marshal.
            logger.error("Error in unpacking the exe. Probably due to version incompability (exe created using python 2 and run this script with python 3)")
            is_error = True

        if not is_error:
            folder_count = len(os.listdir(self.extraction_dir))
            if folder_count >= 1:
                PythonExectable.decompile_pyc(self.extraction_dir, PythonExectable.current_dir_pyc_files(self.extraction_dir))
            else:
                logger.error("Error in unpacking the binary")
                exit(1)
