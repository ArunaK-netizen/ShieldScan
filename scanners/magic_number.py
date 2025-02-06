import magic
import os

def check_file_type(file_path):
    """Verify file type using its magic number."""
    try:
        if not os.path.isfile(file_path):
            return {"Error": "File not found"}

        print("Checking file type...")
        file_type = magic.from_file(file_path)
        file_extension = os.path.splitext(file_path)[-1].lower()

        print(f"Detected Type: {file_type}, Extension: {file_extension}")

        KNOWN_FILE_TYPES = {
            ".exe": "PE32 executable",
            ".jpg": "JPEG image data",
            ".png": "PNG image data",
            ".pdf": "PDF document",
            ".txt": "ASCII text"
        }

        expected_type = KNOWN_FILE_TYPES.get(file_extension)
        if expected_type and expected_type not in file_type:
            print("File type mismatch detected!")
            return "unsafe"

        return "safe"
    except Exception as e:
        return f"Error checking file type: {str(e)}"
