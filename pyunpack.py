#!/usr/bin/env python
import argparse
import logging
import os
from unpacker.pyinstaller import PyInstaller
from unpacker.py2exe import Py2Exe
from unpacker.prepend import MagicPrepend

def parse_args():
    parser = argparse.ArgumentParser(
        description="This program will detect, unpack and decompile binary that is packed in either py2exe or pyinstaller. (Use only one option)"
    )

    parser.add_argument("-i", dest="input", required=False, help="exe that is packed using py2exe or pyinstaller")
    parser.add_argument("-p", dest="prepend", required=False, help="Option that prepend pyc without magic bytes. (Usually for pyinstaller main python file)")
    parser.add_argument("-o", dest="output", required=False, help="folder to store your unpacked and decompiled code. (Otherwise will default to current working directory and inside the folder\"unpacked\")")

    return parser.parse_args()

if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # Get arguments
    args = parse_args()
    in_file = args.input
    out_dir = args.output
    prepend = args.prepend

    if prepend is not None and in_file is not None:
        logger.error("Give pyc file to prepend option. No other options are necesarry.")
        
    elif prepend is None and in_file is not None:

        if out_dir is None:
            out_dir = os.path.basename(in_file) + '_unpacked'

        # Determine packer and unpack PE file
        pyinstaller = PyInstaller(in_file, out_dir)
        py2exe = Py2Exe(in_file, out_dir)

        if pyinstaller.is_magic_recognised():
            # Made by pyinstaller
            logger.info("Selected pyinstaller")
            engine = pyinstaller

        elif py2exe.check_magic():
            # Made by py2exe
            logger.info("Selected py2exe")
            engine = py2exe

        else:
            logger.error("Could not determine packer :(")
            exit(1)

        # Unpack
        engine.unpacked(in_file)

        pyinstaller.close()
        py2exe.close()

    elif prepend is not None and in_file is None:
        magic_prepend = MagicPrepend()
        magic_prepend.prepend(prepend, out_dir)
        logger.info("Python code will be saved in `{}`".format(prepend+'.py'))

    else:
        logger.error("Invalid usage. Use -h for help.")
