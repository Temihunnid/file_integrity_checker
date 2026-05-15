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


