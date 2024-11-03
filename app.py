from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# รายการคำสั่งที่อาจเป็นอันตราย
suspicious_signatures = ["rm -rf", "exec", "system", "wget", "curl", "base64"]

def scan_file(file_path):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for signature in suspicious_signatures:
                if signature in content:
                    return True, file_path
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
    return False, None

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    directory = data.get('directory')
    
    if not directory or not os.path.isdir(directory):
        return jsonify({"error": "Invalid directory path"}), 400

    infected_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            has_virus, infected_file = scan_file(file_path)
            if has_virus:
                infected_files.append(infected_file)

    return jsonify({
        "hasVirus": len(infected_files) > 0,
        "infectedFiles": infected_files
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
