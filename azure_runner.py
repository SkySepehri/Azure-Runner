import subprocess
import os
import re
import json
import websockets
import boto3
import ssl
import certifi
import uuid
import asyncio
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from waitress import serve

AWS_REGION = "ap-southeast-2"
COGNITO_USER_POOL_ID = "ap-southeast-2_UQyJ7Oezq"
COGNITO_CLIENT_ID = "3uj56m95fmrsfercf49rsp4jrb"
AWS_WEBSOCKET_URI = "wss://aqe7h04pwk.execute-api.ap-southeast-2.amazonaws.com/develop/"

ssl_context = ssl.create_default_context(cafile=certifi.where())

app = Flask(__name__)

def get_cognito_token(username, password):
    """Authenticate with AWS Cognito and retrieve an ID token."""
    client = boto3.client("cognito-idp", region_name=AWS_REGION)
    try:
        response = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password
            },
            ClientId=COGNITO_CLIENT_ID
        )
        return response["AuthenticationResult"]["IdToken"]
    except client.exceptions.NotAuthorizedException:
        return "Invalid username or password."
    except Exception as e:
        return f"Failed to authenticate with Cognito: {str(e)}"

async def send_to_aws(action, runId, token, testName, testResult):
    """Send structured message to AWS WebSocket."""
    extra_headers = {"Authorization": token}
    async with websockets.connect(AWS_WEBSOCKET_URI, extra_headers=extra_headers, ssl=ssl_context) as aws_websocket:
        payload = {
            "action": action,
            "runId": runId,
            "token": token,
            "testName": testName,
            "testResult": testResult,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await aws_websocket.send(json.dumps(payload))
        print(f"Sent to AWS: {payload}")

## Formatting Output
def parse_ps_output(raw_text):
    fields = {
        "TechnicalInformation": r'"TechnicalInformation"\s*:\s*"([^"]+)"',
        "WeightedScore": r'"WeightedScore"\s*:\s*([\d.]+)',
        "Category": r'"Category"\s*:\s*"([^"]+)"',
        "ErrorMsg": r'"ErrorMsg"\s*:\s*"([^"]+)"',
        "ItemNumber": r'"ItemNumber"\s*:\s*"([^"]+)"',
        "MITREMapping": r'"MITREMapping"\s*:\s*"([^"]+)"',
        "RemediationSolution": r'"RemedediationSolution"\s*:\s*([\s\S]+?)"(?:,\s*|$)',
        "Status": r'"Status"\s*:\s*"([^"]+)"',
        "TechnicalDetails": r'"TechnicalDetails"\s*:\s*(null|".*?")',
        "UseCase": r'"UseCase"\s*:\s*"([^"]+)"'
    }

    extracted_data = {}
    for key, pattern in fields.items():
        match = re.search(pattern, raw_text, re.DOTALL)
        if match:
            value = match.group(1)
            if value == "null":
                extracted_data[key] = None
            else:
                clean_value = bytes(value, "utf-8").decode("unicode_escape").strip()
                extracted_data[key] = clean_value.strip('"')  
        else:
            extracted_data[key] = None 

    return extracted_data

## Run Scripts
def run_powershell_gettoken(tenant_id, client_id, client_secret):
    script_path = os.path.join(os.getcwd(), "AzureAD", "token", "Get-MSGraphAccessToken.ps1")

    if not os.path.exists(script_path):
        raise FileNotFoundError(f"PowerShell script not found at {script_path}")

    powershell_command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
        f"{tenant_id}",
        f"{client_id}",
        f"{client_secret}"
    ]

    try:
        result = subprocess.run(powershell_command, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if "Successfully Authenticated to Microsoft Graph" in output:
            token = output.split("\n")[-1]
            return token
        else:
            raise ValueError("Authentication Failed.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error executing PowerShell script: {e.stderr}")

async def run_ps1_files_in_directory(azure_token, aws_token, tenant_id, client_id, client_secret):
    directory = os.path.join(os.getcwd(), "AzureAD")
    run_id = str(uuid.uuid4())

    ps1_files = [f for f in os.listdir(directory) if f.endswith('.ps1')]
    for ps1_file in ps1_files:
        script_path = os.path.join(directory, ps1_file)
        if os.path.exists(script_path):
            print(f"Running {ps1_file} with token as parameter.")
            powershell_command = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script_path,
                azure_token,
                tenant_id,
                client_id,
                client_secret
            ]
            try:
                result = subprocess.run(powershell_command, capture_output=True, text=True, check=True)
                
                raw_output = result.stdout.strip()
                formatted_output = parse_ps_output(raw_output)

                await send_to_aws(action="sendmessage", runId=run_id, token=aws_token, testName=ps1_file, testResult=formatted_output)

            except subprocess.CalledProcessError as e:
                print(f"Error executing {ps1_file}: {e.stderr}")
        else:
            print(f"Script {ps1_file} not found in {directory}.")

@app.route("/run", methods=["POST"])
def run_scripts():
    data = request.json
    required_keys = ["TenantID", "ClientID", "ClientSecret", "username", "password"]

    if not all(key in data for key in required_keys):
        return jsonify({"error": "Missing required parameters."}), 400

    try:
        azure_token = run_powershell_gettoken(data["TenantID"], data["ClientID"], data["ClientSecret"])
        aws_token = get_cognito_token(data["username"], data["password"])

        if "Invalid" in aws_token or "Failed" in aws_token:
            return jsonify({"error": aws_token}), 401

        asyncio.run(run_ps1_files_in_directory(azure_token, aws_token, data["TenantID"], data["ClientID"], data["ClientSecret"]))

        return jsonify({"message": "Scripts executed successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("Server is running on port 3000...")
    serve(app, host="0.0.0.0", port=3000)

