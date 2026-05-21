# file_integrity_checker
A File Integrity Checker is a security tool that detects unauthorized changes to critical files by computing and verifying SHA-256 hashes. This project guides you in building a simple, effective tool to monitor file integrity and quickly spot tampering.

## SHA-256
SHA-256, which stands for Secure Hash Algorithm 256-bit, is a cryptographic hash function. It takes any input—like a file, password, or message—and produces a fixed-length 256-bit (32-byte) string of characters, called a hash. Even a tiny change in the input results in a completely different hash, making it extremely sensitive to modifications.

The main feature of SHA-256 is that it is one-way: while it’s easy to compute the hash from the input, it’s practically impossible to reverse the process and retrieve the original data. This ensures that hashes can be safely used to verify data without exposing the actual content, which is crucial for security applications like password storage, digital signatures, and data integrity checks.

In the context of file integrity, SHA-256 hashes serve as a “fingerprint” for a file. By storing the original hash and later recomputing the hash of the file, you can quickly detect whether the file has been altered. If the new hash differs from the stored one, it indicates tampering, corruption, or accidental modification, helping protect sensitive information and maintain system security.

# step-by-step process to solve the problem 

understand input/output
Choose programming language (Python recommended for ease)

define storage format JSON dictionary (file_path:hash)

secure location: use os.path expanduser ("~/.itegrity_check/harshes.json") and create directory with permissions 0o700.

implement command parsing using argparse.

Error handling (permission denied, file not found).

Reporting with colours or simple text.

# Step-by-step implementation Guide

Create a directory name it integrity_checker

```bash
mkdir integrity
```
create a file in the directory and name it hashes.json

```bash
touch hashes.json
```
input this code to the file

```bash
{
    "/var/log/syslog": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "/var/log/auth.log": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
}
```
then save it into the file

open another directory and name it integrity_tool

```bash
mkdir integrity_tool
```

in the directory create a file and name it integrity-check

```bash
cd integrity_tool
touch integrity-check
```
open the file 
```bash
nano integrity-check
```

input this code 
```bash
Log file integrity checker using SHA-256.
Commands: init, check, update
"""

import argparse
import os
import json
import hashlib
from pathlib import Path

# ========== CONFIGURATION ==========
STORAGE_DIR = Path.home() / ".integrity_check"
STORAGE_FILE = STORAGE_DIR / "hashes.json"


# ========== STORAGE HELPERS ==========
def ensure_storage():
    """Create storage directory and file with secure permissions."""
    STORAGE_DIR.mkdir(mode=0o700, exist_ok=True)
    if not STORAGE_FILE.exists():
        STORAGE_FILE.touch(mode=0o600)
        STORAGE_FILE.write_text("{}")


def load_hashes():
    """Load stored hash dictionary from JSON file."""
    ensure_storage()
    with open(STORAGE_FILE, "r") as f:
        return json.load(f)


def save_hashes(hashes):
    """Save hash dictionary to JSON file with secure permissions."""
    ensure_storage()
    with open(STORAGE_FILE, "w") as f:
        json.dump(hashes, f, indent=2)
    os.chmod(STORAGE_FILE, 0o600)


# ========== HASHING UTILITY ==========
def compute_hash(file_path):
    """Return SHA-256 hex digest of a file (reads in chunks for large files)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read in 64KB chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
# ========== FILE COLLECTION ==========
def collect_files(path):
    """
    Return a list of absolute file paths.
    If path is a file, return [path].
    If path is a directory, recursively return all regular files inside.
    """
    path = Path(path).resolve()
    if path.is_file():
        return [str(path)]
    elif path.is_dir():
        files = []
        for root, _, filenames in os.walk(path):
            for f in filenames:
                full = Path(root) / f
                if full.is_file():
                    files.append(str(full))
        return files
    else:
        raise FileNotFoundError(f"Path not found: {path}")


# ========== COMMAND: INIT ==========
def cmd_init(path):
    """Initialize hash database for given path."""
    files = collect_files(path)
    hashes = {}
    for f in files:
        try:
            hashes[f] = compute_hash(f)
            print(f"Hashed: {f}")
        except Exception as e:
            print(f"Error hashing {f}: {e}")
    save_hashes(hashes)
    print(f"Hashes stored successfully for {len(files)} files.")


# ========== COMMAND: CHECK ==========
def cmd_check(path):
    """Check current file hashes against stored hashes."""
    stored = load_hashes()
    files = collect_files(path)

    modified = []
    unmodified = []
    not_initialized = []

    for f in files:
 if f not in stored:
            not_initialized.append(f)
            continue
        try:
            current_hash = compute_hash(f)
            if current_hash == stored[f]:
                unmodified.append(f)
            else:
                modified.append(f)
        except Exception as e:
            print(f"Error reading {f}: {e}")

    # Report results
    for f in modified:
        print(f"Status: Modified - {f}")
    for f in unmodified:
        print(f"Status: Unmodified - {f}")
    for f in not_initialized:
        print(f"Status: Not Initialized - {f}")

    if not modified and not not_initialized:
        print("All checked files are unmodified.")
    elif modified:
        print("Possible tampering detected!")


# ========== COMMAND: UPDATE ==========
def cmd_update(path):
    """Update stored hash for given file(s) to current value."""
    stored = load_hashes()
    files = collect_files(path)

    updated = 0
    for f in files:
        if f not in stored:
            print(f"Skipping {f} – not in stored hashes. Use 'init' first.")
            continue
        try:
            new_hash = compute_hash(f)
            stored[f] = new_hash
            updated += 1
            print(f"Updated: {f}")
        except Exception as e:
            print(f"Error updating {f}: {e}")

    if updated:
        save_hashes(stored)
        print(f"Hash updated successfully for {updated} file(s).")

# ========== MAIN DISPATCHER ==========
def main(): 
    parser = argparse.ArgumentParser(
        description="Log file integrity checker using SHA-256",
        epilog="Example: ./integrity-check init /var/log"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init command
    init_parser = subparsers.add_parser("init", help="Initialize hash database")
    init_parser.add_argument("path", help="File or directory to initialize")

    # check command
    check_parser = subparsers.add_parser("check", help="Check integrity against stored hashes")
    check_parser.add_argument("path", help="File or directory to check")

    # update command
    update_parser = subparsers.add_parser("update", help="Update stored hash for a file")
    update_parser.add_argument("path", help="File or directory to update")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args.path)
    elif args.command == "check":
        cmd_check(args.path)
    elif args.command == "update":
        cmd_update(args.path)


if __name__ == "__main__":
    main()
```
execute the file
```bash
chmod +x integrity-check
```
run the file 
```bash
./integrity-check init /var/log
```







