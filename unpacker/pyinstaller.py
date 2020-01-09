import logging
import os
from unpacker.pyexecutable import PythonExectable
import unpacker.pyinstxtractor as pyinstxtractor

logger = logging.getLogger(__name__)

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
        super().__init__(path, output_dir)
        self.py_inst_archive = pyinstxtractor.PyInstArchive(self.file_path)
        
        # A hack to check the existence of the file
        self.open_executable()
        self.close()

        self.py_inst_archive.open()


    def is_magic_recognised(self):
        return self.py_inst_archive.checkFile()


    def __is_encrypted(self, extracted_binary_path, encrypted_key_path):
        if os.path.exists(extracted_binary_path) and os.path.exists(encrypted_key_path):
            is_decrypt = user_input("[*] Encrypted pyc file is found. Decrypt it? [y/n]")
            if is_decrypt.lower() == "y":
                return True
        return False


    def __get_encryption_key(self, encrypted_key_path):
        try:
            encrypted_key_path_pyc = encrypted_key_path + ".pyc" # For some reason uncompyle6 only works with .pyc extension
            copyfile(encrypted_key_path, encrypted_key_path_pyc)
            if os.path.exists(encrypted_key_path_pyc):
                encrypted_key_path_py = encrypted_key_path + ".py"
                (total, okay, failed, verify_failed) = PythonExectable.decompile_pyc(None, [encrypted_key_path_pyc], encrypted_key_path_py)
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
            logger.error("Exception `{}`".format(e.message))
            exit(1)
        finally:
            if os.path.exists(encrypted_key_path_pyc):
                os.remove(encrypted_key_path_pyc)
            if os.path.exists(encrypted_key_path_py):
                os.remove(encrypted_key_path_py)


    def __decrypt_pyc(self, extracted_binary_path, encryption_key):
        # Code reference from https://0xec.blogspot.sg/2017/02/extracting-encrypted-pyinstaller.html
        from Crypto.Cipher import AES
        import zlib
        crypt_block_size = 16
        encrypted_pyc_folder = os.path.join(extracted_binary_path, "out00-PYZ.pyz_extracted")
        encrypted_pyc_list = os.listdir(encrypted_pyc_folder)
        for x, file_name in enumerate(encrypted_pyc_list):
            # File that is decrypted will end with pyc and file with py extension will not be bothered as well
            if ".pyc.encrypted.pyc" not in file_name and ".pyc.encrypted.py" not in file_name and ".pyc.encrypted" in file_name:
                try:
                    encrypted_pyc = os.path.join(encrypted_pyc_folder, file_name)
                    encrypted_pyc_file = open(encrypted_pyc, 'rb')
                    decrypted_pyc_file = open(encrypted_pyc + ".pyc", 'wb')
                    initialization_vector = encrypted_pyc_file.read(crypt_block_size)
                    cipher = AES.new(encryption_key.encode(), AES.MODE_CFB, initialization_vector)
                    plaintext = zlib.decompress(cipher.decrypt(encrypted_pyc_file.read()))
                    decrypted_pyc_file.write(b'\x03\xf3\x0d\x0a\0\0\0\0')
                    decrypted_pyc_file.write(plaintext)
                    encrypted_pyc_file.close()
                    decrypted_pyc_file.close()
                except Exception as e:
                    logger.error("Exception `{}`".format(e.message))
                    exit(1)
        
        try:
            PythonExectable.decompile_pyc(encrypted_pyc_folder, PythonExectable.current_dir_pyc_files(encrypted_pyc_folder))
        finally:
            for x, file_name in enumerate(PythonExectable.current_dir_pyc_files(encrypted_pyc_folder)):
                full_path = os.path.join(encrypted_pyc_folder, file_name)
                if os.path.exists(full_path):
                    os.remove(full_path)


    # To deal with encrypted pyinstaller binary if it's encrypted
    def __decrypt(self):
        extracted_binary_path = self.extraction_dir
        encrypted_key_path = os.path.join(extracted_binary_path, "pyimod00_crypto_key") 

        if self.__is_encrypted(extracted_binary_path, encrypted_key_path) == True:
            encryption_key = self.__get_encryption_key(encrypted_key_path)
            if encryption_key is not None:
                self.__decrypt_pyc(extracted_binary_path, encryption_key)
        else:
            exit()


    def __pyinstxtractor_extract(self):
        if self.py_inst_archive.getCArchiveInfo():
            self.py_inst_archive.parseTOC()
            self.py_inst_archive.extractFiles(self.extraction_dir)
            logger.info('Successfully extracted pyinstaller exe')


    def unpacked(self, filename):
        logger.info("Unpacking...")
        self.__pyinstxtractor_extract()
        self.__decrypt()
        logger.info("Unpacked successfully!")
