import base64
import subprocess
import requests

payload = base64.b64decode("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
subprocess.run(["powershell", "-Command", "Write-Host risky"])
requests.get("https://example.com")
exec(payload)