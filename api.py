from flask import Flask, request, jsonify  
import requests  # Importing the requests library to make HTTP requests

app = Flask(__name__)

# Replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEy'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

@app.route('/check_ip', methods=['POST'])
def check_ip():
    data = request.json
    ip_address = data.get('ip')
    if not ip_address:
        return jsonify({'error': 'No IP address provided'}), 400

    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }

    response = requests.get(f"{VIRUSTOTAL_URL}{ip_address}", headers=headers)
    
    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({'error': 'Failed to retrieve data from VirusTotal'}), response.status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
