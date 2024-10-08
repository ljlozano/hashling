"""
Hashling

hashling.py

This program is designed for computing and comparing file hashes, managing a database of file hashes,
and handling directories of files with optional filtering and blacklisting.

Features:
- Compute hashes for files using various algorithms (e.g., sha256, md5).
- Compare hashes of two files to check for equality.
- Create and manage a database of file hashes and metadata.
- Hash directories recursively, with options to skip hidden files and apply extension blacklisting.

@todo:
- Implement a arg parsed way to interact with the program instead of a loop.
- Enhance directory hashing with additional traversal methods (?).
- Improve error handling and logging.
- Include test cases and more documentation.
- Integrate directory hash comparisons and versioned file management.
"""

import hashlib
import logging
import sys
import os
import atexit
import utils


# Constants
DB_DIR = './files/db/'
DB_PATH = './files/db/file_hashes.db'
LOG_DIR = './files/log/'
LOG_FILE_NAME = 'hashling_operations.log'


class Hashling:

	def __init__(self, logger, db_path) -> None:
		'''
		Constructor that sets up the logger, database, blacklisted exts, and populates data within db.
		Blacklisted extensions are files that will not be parsed for hashing.

		Args:
			logger (logging.Logger): The logger object to be used for the program.
			db_path (str): The string representation of the full database path to be connected to.

		Returns:
			None
		'''
		self.conn, self.cursor = utils.make_db(db_path)
		utils.make_table(self.conn, self.cursor)
		self.logger = logger
		self.db_path = db_path
		self.blacklist_extensions = ['.py', '.pyc']

	def log_hash_operation(self, file_path: str, hash_value: str) -> None:
		'''
		Outputs a filepath and its hash.

		Args:
			file_path (str): The path of the file that has been hashed.
			hash_value (str): The hash of the file located at file_path.

		Returns:
			None
		'''
		self.logger.debug(f'Computed: {file_path} | Hash: {hash_value}')

	def compute_hash(self, algo: str='sha256', path: str="./files/dir/default1.txt") -> str:
		'''
		Computes the hash for a given file with a variety of hashing algorithms to pick from.

		Args:
			algo (str): The algorithm that will be used to compute the hash of the file. 
						Must be a valid algorithm string.
			path (str): The string representation of the path that contains the file to be hashed.

		Returns:
			The string representation of the hashed file with the chosen hashing algorithm.
		'''
		try:
			with open(path, 'rb') as f:
				hd = hashlib.file_digest(f, algo)
			digest = hd.hexdigest()
			self.log_hash_operation(path, digest)
			return digest
		except FileNotFoundError as e:
			self.logger.debug(f"Could not locate file: {path} while attempting to compute its hash.")
			return ""
		except (OSError, ValueError) as e:
			self.logger.debug(f"Unable to compute hash from {path} using {algo}")
			return ""

	def compare_hashes(self, algo: str='sha256', file1: str='./files/dir/default1.txt', file2: str='./files/dir/default2.txt') -> bool:
		'''
		Compares two files for equality via hashing with a variety of algorithms to utilize.
		If files do not exist, or are unreadable, the hashes will not be computed.

		Args:
			algo (str): The algorithm which to hash the files for comparison.
			file1 (str): The location for the first file to hash for comparison.
			file2 (str): The location for the second file to hash for comparison.

		Returns:
			bool: Whether or not the files are equal after hashing.
		'''
		hash1 = self.compute_hash(path=file1, algo=algo)
		hash2 = self.compute_hash(path=file2, algo=algo)
		if not hash1 or not hash2:
			self.logger.debug(f"Invalid hash for comparison.  Hash1: {hash1} // Hash2: {hash2}")
			return False
		ans = (hash1 == hash2)
		if ans:
			self.logger.debug(f"The files appears to be identical with the matching hashes: {hash1} // {hash2}")
		else:
			self.logger.debug(f"The files appears to different with the following hashes: {hash1} // {hash2}")
		return ans

	def add_blacklist_extension(self, extension: str) -> bool:
		'''
		Adds an extension to the blacklisted extension list.

		Args:
			extension (str): The extension to add to the blacklist of files not to be hashed.

		Returns:
			bool: True if successfully added, otherwise False.
		'''
		self.blacklist_extensions.append(extension)
		return extension in self.blacklist_extensions

	def remove_blacklist_extension(self, extension: str) -> bool:
		'''
		Removes an extension to the blacklisted extension list.

		Args:
			extension (str): The extension to remove from the blacklist of files not to be hashed.

		Returns:
			bool: True if successfully removed, otherwise False.
		'''
		try:
			self.blacklist_extensions.remove(extension)
		except ValueError:
			self.logger.debug(f"Tried to remove extension: {extension} but was not found within extension blacklist.")
		return extension in self.blacklist_extensions

	def get_blacklist_extensions(self) -> list:
		'''
		Returns the list of blacklisted extensions.

		Returns:
			list: Full list of blacklisted extensions to not be hashed.
		'''
		return self.blacklist_extensions

	def is_file_hidden(self, filename: str) -> bool:
		'''
		Checks if a filename (or directory) is hidden

		Args:
			filename (str): The name of the file or folder to check if it's hidden.

		Return:
			bool: Yes if hidden, no if it's not hidden.
		'''
		return filename.startswith(".")

	def is_file_blacklisted(self, filename: str) -> bool:
		'''
		Checks if a given filename contains any blacklisted extensions.

		Args:
			filename (str): The name of the file in string format

		Return:
			bool: Yes if blacklisted, no if not blacklisted.
		'''
		for i in range(len(self.get_blacklist_extensions())):
			if filename.endswith(self.blacklist_extensions[i]):
				self.logger.debug(f"Found blacklisted file and ignored it: {filename}")
				return True
		return False

	def hash_directory(
			self,
			directory: str=os.getcwd(),
			style: str="recur",
			skip_hidden_files: bool=True,
			skip_all_hidden: bool=True,
			extension_blacklisting: bool=True
		) -> None:
		'''
		Hashes all files in a directory and its subdirectories, optionally skipping hidden files and directories,
		respecting file extension blacklists.

		Args:
			directory (str): The directory start hashing from.
			style (str): Method for traversal.  Stack implementation with BFS/DFS is possible. 'recur' for os.walk().
			skip_hidden_files (bool): Whether to skip hidden files.
			skip_all_hidden (bool): Whether to skip all hidden files and directories.
			extension_blacklisting (bool): Whether to apply the blacklisting of file extensions.

		Returns:
			None

		@todo:
			Process file regardless of parent directory status.
			Process file if it exists within a hidden directory.
			Add different ways of directory traversal.
		'''
		hashes = []
		for root, dirs, files in os.walk(directory):
			if skip_all_hidden:
				if extension_blacklisting: # Skip hidden directories and blacklisted files.
					dirs[:] = [d for d in dirs if not self.is_file_hidden(d)] # Skip hidden directories
					files = [f for f in files if not self.is_file_hidden(f) and not self.is_file_blacklisted(f)]
				else:
					dirs[:] = [d for d in dirs if not self.is_file_hidden(d)]
					files = [f for f in files if not self.is_file_hidden(f)]
			else:
				if extension_blacklisting: # Not skipping hidden but skipping blacklisted.
					files = [f for f in files if not self.is_file_blacklisted(f)]				
			for file in files:
				full_path = os.path.join(root, file)
				file_hash = self.compute_hash(path=full_path)
				if file_hash:
					file_size = os.path.getsize(full_path)
					hashes.append((file, file_size, file_hash))
					self.logger.debug(f"Added {file}'s hash: {file_hash} to the database.")
				else:
					self.logger.debug(f"Unable to add {file}'s hash to the database.  Hash: {file_hash}")
		if hashes:
			utils.insert_file_hashes(self.conn, self.cursor, hashes)


def loop(hashling) -> None:
	'''
	Text based command line style interface which allows the user to interact with the program based on input.

	Args:
		hashling (Hashling): The Hashling object that will be used for various hashing purposes.

	Returns:
		None
	'''
	try:
		while True:
			hashling.logger.info("[1] - Compute the hash of a file. ")
			hashling.logger.info("[2] - Compare the hashes of two files for equality. ")
			hashling.logger.info("[3] - Recursively dump all dirs/subdirs/filenames (DEFAULTS TO CWD).")
			hashling.logger.info("[x] - Exit the program. ")
			ans = input("What would you like to do? : ")
			if ans == '1':
				computed_hash = hashling.compute_hash()
			elif ans == '2':
				computed_hashes = hashling.compare_hashes()
			elif ans == '3':
				recursive_dir_hashing = hashling.hash_directory()
			elif ans == 'x':
				hashling.logger.debug("Shutting down...")
				sys.exit()
			else:
				hashling.logger.debug(f"Invalid choice {ans} - please choose from the list.")
	except KeyboardInterrupt:
		hashling.logger.debug("Program halted by user... shutting DB down then closing...")

def setup_directories() -> None:
	utils.create_path(DB_DIR)
	utils.create_path(LOG_DIR)

def close_database(hashling: object) -> None:
	utils.close_db(hashling.conn, hashling.cursor)

def driver() -> None:
	'''
	Main driver function to run the various stages of the program's execution.

	Returns:
		None
	'''
	setup_directories()
	logger = utils.build_logger(LOG_DIR, LOG_FILE_NAME)
	hling = Hashling(logger=logger, db_path=DB_PATH)
	atexit.register(lambda: close_database(hling)) # Close database regardless of how program shuts down.
	hling.logger.debug("Successfully booted.  Welcome!")
	try:
		loop(hling)
	except KeyboardInterrupt:
		hling.logger.debug("Program halted by user...")

if __name__ == '__main__':
	driver()