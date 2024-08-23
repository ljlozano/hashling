'''
Used for computing various hashes of a given file.
Used for comparing the hashes of various files.
Used for creating a versioned master list of hashes and their respective filenames and metadata.

More coming.

Added:
- Logging
- Database
'''
import hashlib
import logging
import sys
import os
import sqlite3
import atexit


# Constants
DB_PATH = './files/db/'


# Database Connection
try:
	if not os.path.exists(DB_PATH):
		os.makedirs(DB_PATH)
		print(f"Created database directory at {DB_PATH}...")
except (FileNotFoundError, OSError) as e:
	print(f"Error while initializing database directory, could not create filepath... {e}")


class Hashling:

	def __init__(self, logger, db_path='./files/db/file_hashes.db') -> None:
		self.logger = logger
		self.db_path = db_path
		self.make_db()
		self.make_table()

	def make_db(self) -> None:
		self.conn = sqlite3.connect(self.db_path)
		self.cursor = self.conn.cursor()

	def make_table(self) -> None:
		self.cursor.execute('''
			CREATE TABLE IF NOT EXISTS file_hashes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				file_name TEXT NOT NULL,
				file_size TEXT NOT NULL,
				file_hash TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
				)
			''')
		self.conn.commit()

	def insert_file_hashes(self, hashes: list) -> None:
		self.cursor.executemany('''
			INSERT INTO file_hashes (file_name, file_size, file_hash)
			VALUES (?, ?, ?)
			''', hashes)
		self.conn.commit()

	def log_hash_operation(self, file_path: str, hash_value: str) -> None:
		self.logger.debug(f'Computed: {file_path} | Hash: {hash_value}')

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

	def hash_directory(self, directory : str=os.getcwd(), style="recur") -> None:
		hashes = []
		for root, dirs, files in os.walk(directory):
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
			self.insert_file_hashes(hashes)


def build_logger() -> logging.Logger:
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.DEBUG)
	log_dir = './files/log/'

	try:
		if not os.path.exists(log_dir):
			os.makedirs(log_dir)
			print(f"Created log directory!")
	except (FileNotFoundError, OSError) as e:
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

def close_db(hashling) -> None:
	if hashling.conn:
		try:
			hashling.cursor.close()
			hashling.conn.close()
		except sqlite3.ProgrammingError as e:
			hashling.logger.debug(f"Could not close database due to error: {e}...")

def loop(hashling) -> None:
	# Text interface
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

def driver() -> None:
	clogger = build_logger()
	hling = Hashling(clogger)
	atexit.register(close_db, hling) # Close database regardless of how program shuts down.
	hling.logger.debug("Successfully booted.  Welcome!")
	try:
		loop(hling)
	except KeyboardInterrupt:
		hling.logger.debug("Program halted by user...")

if __name__ == '__main__':
	driver()