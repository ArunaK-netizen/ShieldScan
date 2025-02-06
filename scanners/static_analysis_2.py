import pefile


def analyze_metadata(file_path):
    """Perform static analysis on Windows executables using metadata."""
    try:
        with open(file_path, 'rb') as file:
            print("Analyzing file metadata...")

        # Load the file using pefile
        pe = pefile.PE(file_path)

        # Extract relevant metadata information
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        image_base = hex(pe.OPTIONAL_HEADER.ImageBase)
        compile_time = pe.FILE_HEADER.TimeDateStamp
        imported_dlls = [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe,
                                                                                                      'DIRECTORY_ENTRY_IMPORT') else []

        print(
            f"Entry Point: {entry_point}, Image Base: {image_base}, Compile Time: {compile_time}, DLLs: {imported_dlls}")

        # Check for suspicious DLLs
        SUSPICIOUS_DLLS = ['ws2_32.dll', 'wininet.dll', 'kernel32.dll']
        for dll in imported_dlls:
            print(f"Checking DLL: {dll}")
            if dll in SUSPICIOUS_DLLS:
                print(f"Suspicious DLL detected: {dll}")
                return "unsafe"

        return "safe"
    except Exception as e:
        return f"Error analyzing metadata: {str(e)}"
