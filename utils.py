"""
utils.py

This module contains utility functions and helpers for Hashling, including database management,
logging setup, and various file system operations.

Overview:
- Provide utility functions and helper methods that do not need to be within the core logic of the other class',
  but support their class' core functionality.
- Establish and manage database connections and operations.
- Create and establish a logger that logs to both the console and a log file.
- Create directories and files as needed to support the application's needs.
- Modularity and portability of code.

@todo:
- Port database connection, cursor handling, logger setup, and directory creation from hashling.py
- Refactor and move relevant logic from `hashling.py` to this module to improve code organization.
"""
import logging
import sqlite3
import os

def make_db(db_path: str) -> tuple:
	'''
	Establishes a connection & cursor to the sqlite3 database.

	Returns:
		None
	'''
	try:
		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()
		return conn, cursor
	except sqlite3.Error as e:
		print(f"Failed to connect due to {e}.") # Swap to logger when built
		return "", ""

def close_db(conn: object, cursor: object) -> None:
	'''
	Closes the connection & cursor to the sqlite3 database (if it is connected).

	Returns:
		None
	'''
	try:
		cursor.close()
		conn.close()
	except sqlite3.ProgrammingError as e:
		logger.debug(f"Could not close database due to error: {e}...")

def make_table(conn: object, cursor: object) -> None:
	'''
	SQL Command to create a file_hashes table (if not already existing) with the following columns:
		id
		file_name
		file_size
		file_hash
		timestamp

	Returns:
		None
	'''
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS file_hashes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_name TEXT NOT NULL,
			file_size TEXT NOT NULL,
			file_hash TEXT NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		''')
	conn.commit()


def insert_file_hashes(conn: object, cursor: object, hashes: list) -> None:
	'''
	SQL Command to insert values into file_hashes table:
		file_name
		file_size
		file_hash

	Args:
		hashes (list): The list of tuples containing the file hash and metadata to insert

	Returns:
		None
	'''
	cursor.executemany('''
		INSERT INTO file_hashes (file_name, file_size, file_hash)
		VALUES (?, ?, ?)
		''', hashes)
	conn.commit()

def build_logger(log_dir: str, log_file: str) -> logging.Logger:
	'''
	Builds a custom logger that logs to both an external log file as well as the console.
	
	Args:
		None
	
	Returns:
		logging.Logger: A Logger object created from the current file.
	'''
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.DEBUG)

	file_handler = logging.FileHandler(os.path.join(log_dir, log_file))
	console_handler = logging.StreamHandler()  # Log to the console
	file_handler.setLevel(logging.DEBUG)
	console_handler.setLevel(logging.DEBUG)
	
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	file_handler.setFormatter(formatter)
	console_handler.setFormatter(formatter)
	logger.addHandler(file_handler)
	logger.addHandler(console_handler)
	return logger

def create_path(directory: str) -> None:
	'''
	Creates a directory from provided directory string parameter.

	Args:
		directory str: A string containing the path of the directory to create.
	
	Returns:
		None
	'''
	try:
		if not os.path.exists(directory):
			os.makedirs(directory)
			print(f"Created directory at {directory}...")
	except (FileNotFoundError, OSError) as e:
		print(f"Error while creating directory, could not create filepath... {e}")