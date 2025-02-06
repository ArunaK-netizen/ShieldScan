import pefile
import os

def static_analysis(file_path):
    """Extract metadata from PE headers for Windows executables."""
    try:
        # Ensure the file is not empty
        if os.path.getsize(file_path) == 0:
            return "File is empty"

        # Check for known PE magic number (MZ header)
        with open(file_path, 'rb') as file:
            magic = file.read(2)
            if magic != b'MZ':
                return "Not a valid PE file"

        # Try to load the PE file
        pe = pefile.PE(file_path)

        # Check if it's a valid executable
        if pe.is_exe() or pe.is_dll():
            suspicious_sections = [section for section in pe.sections if section.SizeOfRawData == 0]
            if suspicious_sections:
                return "unsafe"

            # Check for other suspicious indicators (e.g., strange section names or large entry point size)
            for section in pe.sections:
                if b'.text' in section.Name or b'.data' in section.Name:
                    if section.SizeOfRawData > 0 and section.SizeOfRawData < 200:
                        return "unsafe"

            return "safe"

        return "Not a valid executable or DLL"

    except pefile.PEFormatError as e:
        return f"Invalid PE file format: {str(e)}"
    except Exception as e:
        return f"Error analyzing file: {str(e)}"
