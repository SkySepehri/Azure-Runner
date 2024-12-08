import argparse
import subprocess
import os
import re
import json
import boto3
import websockets
import ssl
import certifi
import uuid
import asyncio
from datetime import datetime, timezone

AWS_REGION = "ap-southeast-2"
COGNITO_USER_POOL_ID = "ap-southeast-2_UQyJ7Oezq"
COGNITO_CLIENT_ID = "3uj56m95fmrsfercf49rsp4jrb"
AWS_WEBSOCKET_URI = "wss://d5dy42u24m.execute-api.ap-southeast-2.amazonaws.com/dev"

ssl_context = ssl.create_default_context(cafile=certifi.where())

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
        print("Invalid username or password.")
    except Exception as e:
        print(f"Failed to authenticate with Cognito: {str(e)}")
    return None

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

## Formating Output
def parse_ps_output(text):
    fields = {
        "TechnicalInformation": r"TechnicalInformation\s+(.+)",
        "WeightedScore": r"WeightedScore\s+(\d+)",
        "Category": r"Category\s+(.+)",
        "ErrorMsg": r"ErrorMsg\s*(.*)",
        "ItemNumber": r"ItemNumber\s+(\S+)",
        "MITREMapping": r"MITREMapping\s+(.+)",
        "RemediationSolution": r"RemediationSolution\s+([\s\S]+?)(?=\s*(?:Status|$))",
        "Status": r"Status\s+(\S+)",
        "TechnicalDetails": r"TechnicalDetails\s+(.+)",
        "UseCase": r"UseCase\s+(.+)"
    }
    
    formatted_output = {}
    
    for field, pattern in fields.items():
        match = re.search(pattern, text)
        if match:
            value = match.group(1).strip()
            formatted_output[field] = value if value else ""
        else:
            formatted_output[field] = ""
    

    # Convert WeightedScore to integer if it exists
    if 'WeightedScore' in formatted_output and formatted_output['WeightedScore']:
        formatted_output['WeightedScore'] = int(formatted_output['WeightedScore'])
    
    # Remove '[MITRE]' from MITREMapping if it exists
    if 'MITREMapping' in formatted_output and formatted_output['MITREMapping']:
        formatted_output['MITREMapping'] = formatted_output['MITREMapping'].replace("[MITRE] ", "")
    
    # Ensure that ErrorMsg is empty and ItemNumber is not part of it
    if 'ItemNumber' in formatted_output and formatted_output['ItemNumber']:
        formatted_output['ErrorMsg'] = ""  # Empty ErrorMsg
        formatted_output['ItemNumber'] = formatted_output['ItemNumber']
    
    return formatted_output

def clean_remediation_solution_spacing(text):
    text = re.sub(r"RemedediationSolution", "RemediationSolution", text)
    # Clean up the space specifically between MITREMapping and RemediationSolution
    text = re.sub(r"(MITREMapping\s+[\s\S]+?)(\s{2,})(RemediationSolution)", r"\1\n\3", text)
    return text

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

async def run_ps1_files_in_directory(azure_token, aws_token):
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
                azure_token
            ]
            try:
                result = subprocess.run(powershell_command, capture_output=True, text=True, check=True)
                
                raw_output = result.stdout.strip()
                cleaned_text = clean_remediation_solution_spacing(raw_output)
                formatted_output = parse_ps_output(cleaned_text)

                await send_to_aws(action="sendmessage", runId=run_id, token=aws_token, testName=ps1_file ,testResult=formatted_output)

            except subprocess.CalledProcessError as e:
                print(f"Error executing {ps1_file}: {e.stderr}")
        else:
            print(f"Script {ps1_file} not found in {directory}.")


def main():
    parser = argparse.ArgumentParser(description="Azure Runner")
    parser.add_argument("-TenantID", required=True, help="Azure Tenant ID")
    parser.add_argument("-ClientID", required=True, help="Azure Client ID")
    parser.add_argument("-ClientSecret", required=True, help="Azure Client Secret")
    parser.add_argument("-username", required=True, help="Azure Username")
    parser.add_argument("-password", required=True, help="Azure Password")

    
    try:
        args = parser.parse_args()
        print(f"Arguments received: TenantID={args.TenantID}, ClientID={args.ClientID}, ClientSecret={args.ClientSecret}, username={args.username}, password={args.password}") 
        
        azure_token = run_powershell_gettoken(args.TenantID, args.ClientID, args.ClientSecret)
        print("Azure Token retrieval successful.")
        
        aws_token = get_cognito_token(args.username, args.password)
        print("AWS Token retrieval successful.")
        
        asyncio.run(run_ps1_files_in_directory(azure_token, aws_token))

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
