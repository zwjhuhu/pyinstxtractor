# -*- coding: utf-8 -*-

"""
本程序改编自 PyInstaller Extractor v1.9 (Supports pyinstaller 3.3, 3.2, 3.1, 3.0, 2.1, 2.0)
Url    : [url]https://sourceforge.net/projects/pyinstallerextractor/[/url]
使用了pyinstxtractor来解压pyinstaller打包的文件
使用解压后的xtracted目录里面的__future.__.pyc文件头作为主程序文件头部分
使用uncompyle6来还原对应的pyc源码
"""
 
from __future__ import print_function
import os,re,glob
import struct
import marshal
import zlib
import sys
import imp
import types
from uuid import uuid4 as uniquename
import  uncompyle6.main as um
import uncompyle6.scanners.scanner36
 
 
class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name
 
 
class PyInstArchive:
    extractionDir=''
    entry=''
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller
 
    def __init__(self, path):
        self.filePath = path
 
 
    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            print('[*] Error: Could not open {0}'.format(self.filePath))
            return False
        return True
 
 
    def close(self):
        try:
            self.fPtr.close()
        except:
            pass
 
 
    def checkFile(self):
        print('[*] Processing {0}'.format(self.filePath))
        # Check if it is a 2.0 archive
        self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))
 
        if magicFromFile == self.MAGIC:
            self.pyinstVer = 20     # pyinstaller 2.0
            print('[*] Pyinstaller version: 2.0')
            return True
 
        # Check for pyinstaller 2.1+ before bailing out
        self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))
 
        if magicFromFile == self.MAGIC:
            print('[*] Pyinstaller version: 2.1+')
            self.pyinstVer = 21     # pyinstaller 2.1+
            return True
 
        print('[*] Error : Unsupported pyinstaller version or not a pyinstaller archive')
        return False
 
 
    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
 
                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver) = \
                struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))
 
            elif self.pyinstVer == 21:
                self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
 
                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver, pylibname) = \
                struct.unpack('!8siiii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))
 
        except:
            print('[*] Error : The file is not a pyinstaller archive')
            return False
 
        print('[*] Python version: {0}'.format(self.pyver))
 
        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen
 
        print('[*] Length of package: {0} bytes'.format(self.overlaySize))
        return True
 
 
    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)
 
        self.tocList = []
        parsedLen = 0
 
        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iiiiBc')
 
            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!iiiBc{0}s'.format(entrySize - nameLen), \
                self.fPtr.read(entrySize - 4))
 
            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                print('[!] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))
 
            self.tocList.append( \
                                CTOCEntry(                      \
                                    self.overlayPos + entryPos, \
                                    cmprsdDataSize,             \
                                    uncmprsdDataSize,           \
                                    cmprsFlag,                  \
                                    typeCmprsData,              \
                                    name                        \
                                ))
 
            parsedLen += entrySize
        print('[*] Found {0} files in CArchive'.format(len(self.tocList)))
 
 
 
    def extractFiles(self):
        print('[*] Beginning extraction...please standby')
        extractionDir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')
        self.extractionDir=extractionDir
 
        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)
 
        os.chdir(extractionDir)
 
        for entry in self.tocList:
            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)
 
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)
 
            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize # Sanity Check
 
            with open(entry.name, 'wb') as f:
                f.write(data)
 
            if entry.typeCmprsData == b's':
                if not re.findall(r'bootstrap$',entry.name):
                    self.entry=entry.name
                print('[+] Possible entry point: {0}'.format(entry.name))
 
            elif entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                self._extractPyz(entry.name)
 
 
    def _extractPyz(self, name):
        dirName =  name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)
 
        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0' # Sanity Check
 
            pycHeader = f.read(4) # Python magic value
 
            if imp.get_magic() != pycHeader:
                print('[!] Warning: The script is running in a different python version than the one used to build the executable')
                print('    Run this script in Python{0} to prevent extraction errors(if any) during unmarshalling'.format(self.pyver))
 
            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)
 
            try:
                toc = marshal.load(f)
            except:
                print('[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return
 
            print('[*] Found {0} files in PYZ archive'.format(len(toc)))
 
            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)
 
            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
 
                fileName = key
                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = key.decode('utf-8')
                except:
                    pass
 
                # Make sure destination directory exists, ensuring we keep inside dirName
                destName = os.path.join(dirName, fileName.replace("..", "__"))
                destDirName = os.path.dirname(destName)
                if not os.path.exists(destDirName):
                    os.makedirs(destDirName)
 
                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(fileName))
                    open(destName + '.pyc.encrypted', 'wb').write(data)
                    continue
 
                with open(destName + '.pyc', 'wb') as pycFile:
                    pycFile.write(pycHeader)      # Write pyc magic
                    pycFile.write(b'\0' * 4)      # Write timestamp
                    if self.pyver >= 33:
                        pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3
                    pycFile.write(data)
 
def modify_pyc(f1,f2,result,pyver):  #use f1 as template , copy its head to f2 , and merge them to result
    #headSize=8是3.5以前版本，3.6版本，headSize=12
    if int(pyver)>=36:
        headSize=12
    else:
        headSize=8
    with open(f1,'rb') as f:
        head=f.read(headSize)
        f.close
    with open(result,'wb') as f:
        f.write(head)
        with open(f2,'rb') as ff:
            ss=ff.read()
            ff.close()
        f.write(ss)
        f.close()
    print("file:%s was written , copied %d bytes from template file." % (result,headSize))

# truncate file otherwise unpack pyinstaller will fail 
def trunFile(path):
    magic = b'MEI\014\013\012\013\016'
    f = open(path, 'rb+')
    fileSize = os.stat(path).st_size
    f.seek(fileSize - 24, os.SEEK_SET)
    magicFromFile = f.read(8)

    if magicFromFile == magic:
        return

    # Check for pyinstaller 2.1+ before bailing out
    f.seek(fileSize - 88, os.SEEK_SET)
    magicFromFile = f.read(8)

    if magicFromFile == magic:
        return

    # find magaic auto and truncate file
    print('magic not found need search')

    pos = fileSize - 88
    for i in range(1,pos):
        f.seek(pos - i)
        magicFromFile = f.read(8)
        if magicFromFile == magic:
            pos = pos -i 
            print('find magic in pos ',pos);
            break
    if pos < fileSize - 88:
        f.read(80)
        print('Warn: will truncate file to %d' % (pos + 88))
        f.truncate()

    f.close()   
    
     

def main():
    if len(sys.argv) < 2:
        print('[*] Usage: decompile_python.py <filename.exe>')
    else:
        trunFile(sys.argv[1]) 
        arch = PyInstArchive(sys.argv[1])
        if arch.open():
            if arch.checkFile():
                if arch.getCArchiveInfo():
                    arch.parseTOC()
                    arch.extractFiles()
                    arch.close()
                    os.chdir('..')
                    print("python version is %s" % arch.pyver)
                    entry=arch.extractionDir+"/"+arch.entry
                    entry_pyc=arch.entry+".pyc"
                    temp_file=glob.glob(arch.extractionDir+"/*/__future__.pyc")[0]
                    print("extract=%s,arch.entry=%s" % (arch.extractionDir,arch.entry)) 
                    print("temp_file="+temp_file)
                    print("entry=%s,entry_pyc=%s,arch.pyver=%s" % (entry,entry_pyc,arch.pyver))
                    modify_pyc(temp_file,entry,entry_pyc,arch.pyver)
                    print("result pyc file is :"+entry_pyc)
                    um.main('.','.',[entry_pyc],[],outfile="%s.py" % arch.entry)
                    print("result source code py file is %s.py" % arch.entry)
                    #os.system("notepad %s.py" % arch.entry)
                    return
 
            arch.close()
 
 
if __name__ == '__main__':
    main()