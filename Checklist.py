import os
import sys
import json
import base64
import requests
import textwrap
from openrouter import OpenRouter

# 1. Initialize API Clients from Environment Variables
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
MODEL = "openrouter/free"


if not OPENROUTER_API_KEY:
    print("[!] Error: OPENROUTER_API_KEY environment variable is not set.")
    sys.exit(1)

client = OpenRouter(api_key=OPENROUTER_API_KEY)


def load_benchmarks_from_json(file_path="security_benchmarks.json"):
    """Loads complete benchmarks (Stage, Severity, Control & Description) from a local JSON file."""
    if not os.path.exists(file_path):
        print(f"[!] Benchmark file not found at: {file_path}")
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        formatted_list = []

        # Iterate through the list of benchmarks
        for item in data.get("benchmarks", []):
            # Extract each individual field safely with default fallbacks
            control = item.get('control', 'Unknown Control')
            stage = item.get('stage', 'global').upper()
            severity = item.get('severity', 'Medium').upper()
            description = item.get('description', '')

            # Combine them into a highly descriptive string for the LLM prompt
            benchmark_line = f"- [{stage}] [SEVERITY: {severity}] {control}: {description}"
            formatted_list.append(benchmark_line)

        return "\n".join(formatted_list)
    except Exception as e:
        print(f"[!] Error reading JSON benchmarks: {e}")
        return None


def get_pipeline_files_from_github(repo_owner, repo_name):
    """Fetches the text content of all YAML files from the remote GitHub directory."""
    #target_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/.github/workflows"
    target_url = f"https://api.github.com/repos/wrkode/virtrigaud/contents/.github/workflows"
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

def analyze_all_pipelines_batch(files_dictionary, benchmarks_text):
    """Bundles all YAML files together to run a single batch audit, returning ONLY missing controls."""

    system_instruction = (
        "You are an expert DevSecOps compliance auditor. Your job is to verify whether the provided "
        "CI/CD pipeline configurations satisfy our mandatory security controls. "
        "CRITICAL RULE: You must only output findings where the status is 'MISSING'. "
        "Do not include controls that are 'IMPLEMENTED' or 'NOT APPLICABLE' in your output array. "
        "You must output your findings exclusively as a flat raw JSON array of objects."
    )

    yaml_payload_text = ""
    for filename, content in files_dictionary.items():
        yaml_payload_text += f"\n--- START OF FILE: {filename} ---\n{content}\n--- END OF FILE: {filename} ---\n"

    user_prompt =f"""
    Audit the following collection of YAML configuration files as a UNIFIED CI/CD pipeline network.
    
    CRITICAL COGNITIVE RULES TO PREVENT DUPLICATES:
    1. Do NOT evaluate files in isolation. Evaluate the repository as a whole ecosystem.
    2. A security control only belongs in its logical stage (e.g., Secret Scanning belongs in pre-build/test). 
    3. If a security control is successfully implemented in AT LEAST ONE relevant workflow file (e.g., secret scanning runs in ci.yml), then that control is considered COMPLIANT for the entire repository. Do NOT mark it as MISSING in other files like deploy.yml or build.yml.
    4. Only flag a control as MISSING if it is completely absent across the ENTIRE repository where it should logically be running.
    
    Return a unified flat JSON list of objects matching exactly this schema:
    [
      {{
        "filename": "The primary file where this gap exists or where it should logically be fixed",
        "control": "Name of the security control",
        "stage": "The stage of the control (e.g., pre-build, build, test, deploy)",
        "severity": "CRITICAL, HIGH, MEDIUM, or LOW",
        "status": "MISSING",
        "evidence": "Clear explanation of why this control is absent across the pipeline ecosystem",
        "action_required": "Remediation step required to fix this global pipeline gap"
      }}
    ]
    
    REQUIRED GLOBAL BENCHMARKS TO TEST AGAINST:
    {benchmarks_text}
    
    REPOSITORY YAML PIPELINE FILES (THE Ecosystem):
    {yaml_payload_text}
    """

    try:
        # Core OpenRouter cloud generation connection block
        response = client.chat.send(
            model=MODEL,  # This was pointed to "openrouter/free" or a single string
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1  # Low temperature keeps the structure clean and predictable
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[!] OpenRouter Cloud Completion processing failed: {e}"

def convert_json_to_fixed_table(json_string):
    try:
        # Clean potential markdown wrappers around the JSON block
        clean_json = json_string.strip().strip("`").replace("json\n", "")
        audit_data = json.loads(clean_json)

        # 1. Set fixed widths for all 6 columns now
        w_control, w_stage, w_severity, w_status, w_evidence, w_action = 18, 10, 10, 12, 30, 25

        # 2. Define our 6-column text format string and a clean geometric line divider
        row_fmt = "| {:<18} | {:<10} | {:<10} | {:<12} | {:<30} | {:<25} |"
        divider = "+" + "-" * 20 + "+" + "-" * 12 + "+" + "-" * 12 + "+" + "-" * 14 + "+" + "-" * 32 + "+" + "-" * 27 + "+"

        # Initialize the table with headers
        lines = [
            divider,
            row_fmt.format("Security Control", "Stage", "Severity", "Status", "Evidence", "Action Required"),
            divider
        ]

        for item in audit_data:
            # 3. Wrap long sentences smoothly inside their column text boundaries
            c_lines = textwrap.wrap(item.get("control", "N/A"), width=w_control) or [""]
            st_lines = textwrap.wrap(item.get("stage", "N/A"), width=w_stage) or [""]
            sev_lines = textwrap.wrap(item.get("severity", "N/A"), width=w_severity) or [""]
            s_lines = textwrap.wrap(item.get("status", "N/A"), width=w_status) or [""]
            e_lines = textwrap.wrap(item.get("evidence", "N/A"), width=w_evidence) or [""]
            a_lines = textwrap.wrap(item.get("action_required", "N/A"), width=w_action) or [""]

            # Find the vertical line height needed for the current row
            max_rows = max(len(c_lines), len(st_lines), len(sev_lines), len(s_lines), len(e_lines), len(a_lines))

            # 4. Construct the stackesad row line-by-line
            for i in range(max_rows):
                c = c_lines[i] if i < len(c_lines) else ""
                st = st_lines[i] if i < len(st_lines) else ""
                sev = sev_lines[i] if i < len(sev_lines) else ""
                s = s_lines[i] if i < len(s_lines) else ""
                e = e_lines[i] if i < len(e_lines) else ""
                a = a_lines[i] if i < len(a_lines) else ""
                lines.append(row_fmt.format(c, st, sev, s, e, a))

            lines.append(divider)

        return "\n".join(lines)
    except Exception as e:
        return f"[!] Table conversion failed: {e}\n{json_string}"

if __name__ == "__main__":
    # 1. Ask user interactively for target repository
    owner = input("Enter GitHub Organization/Owner (e.g., kubernetes): ").strip()
    repo = input("Enter Repository Name (e.g., grievances): ").strip()

    if not owner or not repo:
        print("[!] Target repository details cannot be empty.")
        sys.exit(1)

    # 2. Extract benchmarks string from your clean JSON
    benchmarks = load_benchmarks_from_json("security_benchmarks.json")

    if benchmarks:
        # --- NEW METRIC: Calculate Total Controls from JSON Data ---
        try:
            with open("security_benchmarks.json", "r", encoding="utf-8") as bf:
                benchmark_data = json.load(bf)

            # If your JSON is a top-level list of controls:
            if isinstance(benchmark_data, list):
                total_controls_count = len([item for item in benchmark_data if "control" in item])
            # If your JSON has a top-level object containing a list (e.g., {"controls": [...]})
            elif isinstance(benchmark_data, dict):
                # We find the list within the dictionary keys dynamically
                list_key = next((k for k, v in benchmark_data.items() if isinstance(v, list)), None)
                if list_key:
                    total_controls_count = len([item for item in benchmark_data[list_key] if "control" in item])
                else:
                    total_controls_count = len(benchmark_data)
            else:
                total_controls_count = 0

            print(f" Loaded security checklist containing {total_controls_count} mandatory control rules.")

        except Exception as err:
            print(f"Could not parse benchmark metrics from file: {err}")

        # 3. Pull target YAML definitions from GitHub contents endpoint
        workflows = get_pipeline_files_from_github(owner, repo)

        if not workflows:
            print("[*] No workflow configurations found to audit.")
        else:
            print(f"\n[*] Found {len(workflows)} workflow file(s). Starting the Scan....")

            print(f"\n" + "-" * 105)
            print(f"SECURITY CONTROLS ON PIPELINE: {owner}/{repo}".center(105))
            print("-" * 105)

            # Pass the complete dictionary of workflows straight to the batch function
            raw_ai_response = analyze_all_pipelines_batch(workflows, benchmarks)

            try:
                # 1. Parse the AI response to verify it's valid JSON
                raw_results = json.loads(raw_ai_response)

                # 2. Filter the array to keep only rows where the status is MISSING
                filtered_results = [row for row in raw_results if row.get("status") == "MISSING"]

                # --- METRIC: Count Missing Controls Found ---
                missing_controls_count = len(filtered_results)

                # 3. Re-serialize back to a string and send to your existing formatter
                clean_json_for_table = json.dumps(filtered_results)
                report_table = convert_json_to_fixed_table(clean_json_for_table)
                print(report_table)

                # 4. Print metrics summary at the very bottom
                print("-" * 105)
                if missing_controls_count == 0:
                    print(
                        f"AUDIT SUCCESS: 0 gaps found. All processed workflows comply with your security checklist.")
                else:
                    print(
                        f"AUDIT ALERT: Found {missing_controls_count} missing security control gap(s) across your workflows!")
                print("-" * 105)

            except Exception as json_err:
                # Fallback if the OpenRouter endpoint fails or returns plain text errors
                print(f"\n[!] Could not generate table dashboard. Raw engine response:")
                print(raw_ai_response)