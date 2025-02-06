import re

SUSPICIOUS_PATTERNS = [
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    b"system\(",
    b"exec\(",
    b"os\.remove",
    b"subprocess\.Popen"
]

def heuristic_scan(file_path):
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                print("Scanning chunk:", chunk)
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, chunk):
                        print(f"Pattern detected: {pattern}")
                        return "unsafe"
        return "safe"
    except Exception as e:
        return f"Error scanning file: {str(e)}"
