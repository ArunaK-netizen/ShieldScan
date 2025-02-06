import hashlib

# Custom hash for "MY-TEST-VIRUS-SIMULATION"
MALICIOUS_HASHES = [
    "26dbbd1bff1c5e40c8b7e6b7307b1e4e"  # MD5 hash for "MY-TEST-VIRUS-SIMULATION"
]

def hash_scan(file_path):
    """Calculate the file's MD5 hash and check if it's in the malicious hash list."""
    try:
        file_hash = hashlib.md5()
        with open(file_path, 'rb') as file:
            print("[DEBUG] Reading file for hash scan...")
            content = file.read()  # Read entire file for testing
            print(f"[DEBUG] File content: {content}")
            file_hash.update(content)

        calculated_hash = file_hash.hexdigest()
        print(f"[DEBUG] Calculated Hash: {calculated_hash}")

        if calculated_hash in MALICIOUS_HASHES:
            print("[DEBUG] Hash match found: File is unsafe")
            return "unsafe"
        print("[DEBUG] Hash not found in database: File is safe")
        return "safe"
    except Exception as e:
        print(f"[ERROR] Hash scan failed: {e}")
        return "error"
