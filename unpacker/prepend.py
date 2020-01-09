import os
import logging
from shutil import copyfile
from unpacker.pyexecutable import PythonExectable, FileNotFoundException

logger = logging.getLogger(__name__)

class MagicPrepend(object):
    # Occasionaly, the main python file that is packed with pyinstaller might not be easily decompiled. This will need to prepend magic bytes into it.
    def prepend(self, main_pyc, out_dir):
        import tempfile

        is_prepend_magic = True
        edited_py_name = main_pyc + ".py"
        edited_pyc = tempfile.NamedTemporaryFile(mode='wb',suffix='.pyc',delete=False)
        try:
            if not os.path.exists(main_pyc):
                raise FileNotFoundException

            # Check if this pyc file is prepended with recognize magic bytes already.
            with open(main_pyc, 'rb') as tmp_pyc:
                from xdis import magics
                py_ver_num = magics.magic2int(tmp_pyc.read(4))
                for key in magics.versions:
                    if magics.magic2int(key) == py_ver_num:
                        logger.info("Magic bytes is already appeneded.")
                        is_prepend_magic = False
                copyfile(main_pyc, edited_pyc.name)

            if is_prepend_magic:
                magic = b'\x42\x0d\x0d\x0a' # Default magic for python 2.7
                with edited_pyc as prepend_pyc:
                    pyc_data = open(main_pyc, 'rb')
                    prepend_pyc.write(magic) # Magic bytes 
                    prepend_pyc.write(b'\0' * 12) # Time stamp
                    prepend_pyc.write(pyc_data.read())
                    pyc_data.close()

            (total, okay, failed, verify_failed) = PythonExectable.decompile_pyc('', [edited_pyc.name], edited_py_name)
            if failed == 0 and verify_failed == 0:
                logger.info("Successfully decompiled.")
            else:
                logger.info("Unable to decompile the pyc file. (Probably is already decompiled?)")
                if os.path.exists(edited_py_name):
                    os.remove(edited_py_name)
                exit(1)

        except FileNotFoundException:
            logger.error("pyc file not found. Ignoring it now.")
            exit(1)
        finally:
            if os.path.exists(edited_pyc.name):
                os.remove(edited_pyc.name)
