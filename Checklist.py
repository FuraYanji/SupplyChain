import os
import sys
import json
import base64
import requests
from openrouter import OpenRouter

# 1. Initialize API Clients from Environment Variables
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
MODEL_NAME = "openrouter/free"

if not OPENROUTER_API_KEY:
    print("[!] Error: OPENROUTER_API_KEY environment variable is not set.")
    sys.exit(1)

client = OpenRouter(api_key=OPENROUTER_API_KEY)


def load_benchmarks_from_json(file_path="security_benchmarks.json"):
    """Loads simplified benchmarks (Control & Description) from a local JSON file."""
    if not os.path.exists(file_path):
        print(f"[!] Benchmark file not found at: {file_path}")
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        formatted_list = []
        for item in data.get("benchmarks", []):
            formatted_list.append(f"- {item['control']}: {item['description']}")
        return "\n".join(formatted_list)
    except Exception as e:
        print(f"[!] Error reading JSON benchmarks: {e}")
        return None


def get_pipeline_files_from_github(repo_owner, repo_name):
    """Fetches the text content of all YAML files from the remote GitHub directory."""
    target_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/.github/workflows"
    headers = {"Accept": "application/vnd.github.v3+json"}

    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    response = requests.get(target_url, headers=headers)
    if response.status_code == 404:
        print("[!] No `.github/workflows` directory found in this repository.")
        return {}
    elif response.status_code != 200:
        print(f"[!] GitHub API error: {response.status_code}")
        return {}

    workflow_contents = {}
    files = response.json()

    for file in files:
        if file["name"].endswith((".yml", ".yaml")) and file["type"] == "file":
            file_response = requests.get(file["url"], headers=headers)
            if file_response.status_code == 200:
                file_data = file_response.json()
                decoded_content = base64.b64decode(file_data["content"]).decode("utf-8")
                workflow_contents[file["name"]] = decoded_content

    return workflow_contents


def analyze_pipeline_with_openrouter(yaml_content, benchmarks_text, filename):
    """Sends the workflow and controls to OpenRouter and mandates a tabular format response."""
    # Precise, direct instructions for OpenAI/OpenRouter models
    system_instruction = (
        "You are an expert DevSecOps compliance auditor. Your job is to verify whether the provided "
        "CI/CD pipeline configuration satisfies our list of mandatory security controls. "
        "You must output your findings exclusively in a clean Markdown table format."
    )

    user_prompt = f"""
Please audit the following CI/CD configuration file against our required security benchmarks.

REQUIRED BENCHMARKS:
{benchmarks_text}

YAML PIPELINE FILE CONTENT ({filename}):
```yaml
{yaml_content}
```
"""

    try:
        # Core OpenRouter cloud generation connection block
        response = client.chat.send(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1  # Low temperature keeps the structure clean and predictable
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[!] OpenRouter Cloud Completion processing failed: {e}"


if __name__ == "__main__":
    print("=== Interactive DevSecOps Pipeline Auditor ===")
    # 1. Ask user interactively for target repository
    owner = input("Enter GitHub Organization/Owner (e.g., kubernetes): ").strip()
    repo = input("Enter Repository Name (e.g., grievances): ").strip()

    if not owner or not repo:
        print("[!] Target repository details cannot be empty.")
        sys.exit(1)

    # 2. Extract benchmarks string from your clean JSON
    benchmarks = load_benchmarks_from_json("security_benchmarks.json")

    if benchmarks:
        # 3. Pull target YAML definitions from GitHub contents endpoint
        workflows = get_pipeline_files_from_github(owner, repo)

        if not workflows:
            print("[*] No workflow configurations found to audit.")
        else:
            print(f"\n[*] Found {len(workflows)} workflow file(s). Starting AI audit scans...")

            # 4. Map findings across every individual workflow file
            for filename, yaml_text in workflows.items():
                print(f"\n" + "="*60)
                print(f"AUDIT REPORT FOR CONFIGURATION: {filename}")
                print("="*60)

                report_table = analyze_pipeline_with_openrouter(yaml_text, benchmarks, filename)
                print(report_table)