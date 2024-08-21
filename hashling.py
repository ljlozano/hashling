'''
Used for computing various hashes of a given file.
Used for comparing the hashes of two files.
+ More coming.

Added:
- Logging
'''
import hashlib
import logging
import sys
import os


class Hashling:

	def __init__(self, logger) -> None:
		self.logger = logger

	def log_hash_operation(self, file_path: str, hash_value: str) -> None:
		self.logger.debug(f'Hashed file: {file_path}, Hash: {hash_value}')

	def compute_hash(self, algo: str = 'sha256', path: str = "./files/dir/default1.txt") -> str:
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

	def compare_hashes(self, algo: str = 'sha256', file1: str = './files/dir/default1.txt', file2: str = './files/dir/default2.txt') -> bool:
		# Improve by taking an array of hash locations to compute for equality rather than being limited to 2.
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

	def hash_directory(self, directory : str=os.getcwd(), style="recur") -> dict:
		hash_directory = {}
		for root, dirs, files in os.walk(directory):
			if len(directory) < 1:
				self.logger.debug(f"Directory: {directory} is empty or inaccessible.")
			self.logger.debug(f"Found the following roots: {root} - (located in {directory})")
			if len(dirs) < 1:
				self.logger.debug(f"There appears to be no subdirectories located within {root}: {dirs} - (located in {directory})")
			else:
				self.logger.debug(f"Found the following directories within {root}: {dirs} - (located in {directory})")
			if len(files) > 0:
				self.logger.debug(f"Hashing {len(files)} within root dir: {directory}...")
				for file in files:
					hash_directory[file] = self.compute_hash(path=directory + "./files/dir/hashall/" + file)
				self.logger.debug(f"Finished hashing {len(files)} within root dir: {directory}...")
			if len(files) > 0 and len(directory) > 0:
				self.logger.debug(f"Found the following files located within all subdirs of {root}: {files} - (located in {directory})")
		return hash_directory



def build_logger() -> logging.Logger:
	# Custom logger
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.DEBUG)
	log_dir = './files/log/'

	try:
		if not os.path.exists(log_dir):
			os.makedirs(log_dir)
			print(f"Created log directory!")
	except FileNotFoundError as e:
		print(f"Error while initializing logger, could not create filepath... {e}")

	file_handler = logging.FileHandler(os.path.join(log_dir, 'hashling_operations.log'))
	console_handler = logging.StreamHandler()  # Log to the console
	file_handler.setLevel(logging.DEBUG)
	console_handler.setLevel(logging.DEBUG)
	
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	file_handler.setFormatter(formatter)
	console_handler.setFormatter(formatter)
	logger.addHandler(file_handler)
	logger.addHandler(console_handler)
	return logger


def loop(hashling) -> None:
	# Text interface.
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

def driver() -> None:
	clogger = build_logger()
	hling = Hashling(clogger)
	hling.logger.debug("Successfully booted.  Welcome!")
	loop(hling)

if __name__ == '__main__':
	driver()