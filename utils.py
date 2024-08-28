"""
utils.py

This module contains utility functions and helpers for Hashling, including database management,
logging setup, and various file system operations.

Overview:
- Provide utility functions and helper methods that do not need to be within the core logic of the Hashling class,
  but support Hashling class' core functionality.
- Establish and manage database connections and operations.
- Create and establish a logger that logs to both the console and a log file.
- Create directories and files as needed to support the application's needs.

@todo:
- Port database connection, cursor handling, logger setup, and directory creation from hashling.py
- Refactor and move relevant logic from `hashling.py` to this module to improve code organization.
"""