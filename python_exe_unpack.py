#!/usr/bin/python
'''
Author: In Ming Loh
Email: inming.loh@countercept.com
'''
from __future__ import print_function
from shutil import copyfile, make_archive
import sys, os, struct, abc, argparse

import pefile
import pyinstxtractor
import uncompyle6
from unpy2exe import unpy2exe

from assemblyline.common.dict_utils import flatten
from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

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

	def __init__(self, path, output_dir):
		self.file_path = path
		self.extraction_dir = output_dir


	def open_executable(self):
		self.fPtr = open(self.file_path, 'rb')
		self.fileSize = os.stat(self.file_path).st_size


	def close(self):
		try:
			self.fPtr.close()
		except:
			pass


	@staticmethod
	def decompile_pyc(dir_decompiled, pyc_files, output_file=None):
		return uncompyle6.main.main(dir_decompiled, dir_decompiled, pyc_files, None, output_file)
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

	def __init__(self, path, output_dir):
		super(PyInstaller, self).__init__(path, output_dir)
		self.py_inst_archive = pyinstxtractor.PyInstArchive(self.file_path)

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
			print("[-] Exception occured while trying to get the encryption key.")
			print("[-] Error message: {0}".format(e.message))
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
					print("[-] Exception occured during pyc decryption and decompiling")
					print("[-] Error message: {0}".format(e.message))

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


	def __pyinstxtractor_extract(self):
		if self.py_inst_archive.getCArchiveInfo():
			self.py_inst_archive.parseTOC()
			self.py_inst_archive.extractFiles(self.extraction_dir)
			print('[*] Successfully extracted pyinstaller exe.')


	def unpacked(self, filename):
		print("[*] Unpacking the binary now")
		self.__pyinstxtractor_extract()
		#self.__decrypt()
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
				PythonExectable.decompile_pyc(self.extraction_dir, PythonExectable.current_dir_pyc_files(self.extraction_dir))
			else:
				print("[-] Error in unpacking the binary")


class PythonExeUnpack(ServiceBase):
	def __init__(self, config=None):
		super(PythonExeUnpack, self).__init__(config)

	def start(self):
		self.log.debug("Document preview service started")

	def stop(self):
		self.log.debug("Document preview service ended")

	def execute(self, request):
		result = Result()
		os.mkdir(self.working_directory + "/unpacked")
		output_dir = self.working_directory + "/unpacked"
		file_name = request.file_path

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

		if os.listdir(self.working_directory + "/unpacked"):
			text_section = ResultSection('Binary successfully unpacked')

			make_archive(self.working_directory + "/unpacked", 'zip', output_dir)
			request.add_extracted(self.working_directory + "/unpacked.zip", "unpacked.zip", "All extracted files")
			result.add_section(text_section)

		request.result = result