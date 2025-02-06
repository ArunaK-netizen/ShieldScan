import re

# Predefined malicious signatures
MALICIOUS_SIGNATURES = [
    b"malware",
    b"ransomware",
    b"virus"
]

def signature_scan(file_path):
    """Check for predefined signatures in the file content."""
    try:
        with open(file_path, 'rb') as file:
            # Read the file in chunks to avoid memory issues with large files
            while chunk := file.read(8192):  # Read 8KB chunks
                for signature in MALICIOUS_SIGNATURES:
                    if signature in chunk:
                        return "unsafe"
        return "safe"
    except Exception as e:
        return f"Error scanning file: {str(e)}"
