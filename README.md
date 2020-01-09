**This repository is forked from [python-exe-unpacker](https://github.com/countercept/python-exe-unpacker).
Most of the source code are based on python-exe-unpacker but some changes have been made to the original code.**

Author: In Ming Loh (inming.loh@countercept.com - @tantaryu) <br />
Company: Countercept (@countercept) <br />
Website: https://www.countercept.com <br />

Revised by: [ptr-yudai](https://twitter.com/ptrYudai)

## Introduction
A script that helps researcher to unpack and decompile executable written in python. However, right now this only supports executable created with py2exe and pyinstaller.

This script glues together several tools available to the community. Hopefully, this can help people in their daily job. Several YARA rules are available to determine if the executable is written in python (This script also confirms if the executable is created with either py2exe or pyinstaller).

## Requirements
- Python 2.x or 3.x
- Install all the dependency needed:<br/>
    `pip install --user -r requirements.txt`<br/>
        or if you fancy to have your dependency installed with root permission<br/>
    `sudo pip install -r requirements.txt`

## How to decompyle
Unpack the binary
```
$ ./pyunpack.py -i malware.exe
```
This will unpack files to `malware.exe_unpacked`.
You can change the output directory with `-o` option.

If you want to decompile a pyc file to Python code, use `-p` option.
```
$ ./pyunpack.py -p malware.exe_unpacked/malware.exe/malware
```
It automatically fixes the header and output the code to `[file name].py` even though the main pyc file lacks its header.

## Credits
- [python-exe-unpacker](https://github.com/countercept/python-exe-unpacker)
