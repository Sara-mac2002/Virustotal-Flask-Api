from flask import Flask, request, jsonify  # Importing necessary parts from Flask
import requests  # Importing the requests library to make HTTP requests

# Step 1: Initialize the Flask application
app = Flask(__name__)

# Replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEy'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

# Step 2: Define an API route that listens for requests at '/check-ip'
@app.route('/check_ip', methods=['POST'])
def check_ip():
    # Step 3: Retrieve the IP address from the client's request
    data = request.json
    ip_address = data.get('ip')
    # Check if the IP address was provided, otherwise return an error
    if not ip_address:
        return jsonify({'error': 'No IP address provided'}), 400

    # Step 4: Set up the request headers with the VirusTotal API key
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }

    # Step 5: Send a GET request to VirusTotal to check the IP
    response = requests.get(f"{VIRUSTOTAL_URL}{ip_address}", headers=headers)
    
    # Step 6: Return the response from VirusTotal to the client
    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({'error': 'Failed to retrieve data from VirusTotal'}), response.status_code

# Step 7: Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
