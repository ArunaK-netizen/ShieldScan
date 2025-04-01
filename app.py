from flask import Flask, request, render_template, jsonify
import os
import mimetypes

app = Flask(__name__)

# Define a folder to save uploaded files
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Allowed file extensions for safety
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt'}


def is_file_safe(file_path):
    """
    Perform checks to determine if the file is safe.
    Example: Checking file type and other criteria.
    """
    # Get the file extension
    mimetype, _ = mimetypes.guess_type(file_path)
    extension = os.path.splitext(file_path)[1].lower().lstrip('.')

    # Check if the extension is allowed
    if extension not in ALLOWED_EXTENSIONS:
        return False, f"File type not allowed: {extension}"

    # Placeholder: Add virus scanning or content scanning logic here
    # Example: Scan with ClamAV, VirusTotal, etc.

    return True, "File is safe"


@app.route('/')
def index():
    """
    Render the file upload form.
    """
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handle the file upload and determine if it's safe or not.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400

    if file:
        # Save the uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Check if the file is safe or not
        is_safe, message = is_file_safe(file_path)

        # Result based on file safety
        result_message = f"File '{file.filename}' uploaded and processed successfully!"
        if is_safe:
            return jsonify({'message': result_message, 'status': 'Safe', 'details': message}), 200
        else:
            return jsonify({'message': result_message, 'status': 'Not Safe', 'details': message}), 400


if __name__ == '__main__':
    app.run(debug=True)
