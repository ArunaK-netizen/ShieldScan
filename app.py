import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanners.hash_scanner import hash_scan
from scanners.heuristic_scanner import heuristic_scan
from scanners.entropy_analysis import calculate_entropy
# from scanners.magic_number import check_file_type
from scanners.static_analysis_2 import analyze_metadata
from scanners.Yara import yara_scan

app = Flask(__name__)
CORS(app)


@app.route('/')
def home():
    return "File Scanner API is running!"


@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    file_path = os.path.join("uploads", uploaded_file.filename)
    os.makedirs("uploads", exist_ok=True)
    uploaded_file.save(file_path)
    print(f"[DEBUG] File uploaded to: {file_path}")

    try:
        # Check if the file was saved correctly
        with open(file_path, 'rb') as f:
            print(f"[DEBUG] Uploaded file content: {f.read()}")

        # Run scans
        print("[DEBUG] Running hash scan...")
        hash_result = hash_scan(file_path)

        print("[DEBUG] Running heuristic scan...")
        heuristic_result = heuristic_scan(file_path)

        entropy_result = calculate_entropy(file_path)
        # magic_number_result = check_file_type(file_path)
        static_analysis_result = analyze_metadata(file_path)
        yara_result = yara_scan(file_path)

        results = {
            "hash_scan": hash_result,
            "heuristic_scan": heuristic_result,
            "entropy_scan": entropy_result,
            # "magic_number_scan": magic_number_result,
            "static_analysis_scan": static_analysis_result,
            "yara_scan": yara_result
        }

        is_safe = all(result == "safe" for result in results.values())
        status = "safe" if is_safe else "unsafe"

        return jsonify({"message": "File scanned", "status": status, "results": results}), 200

    except Exception as e:
        return jsonify({"error": f"Scanning failed: {str(e)}"}), 500
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
