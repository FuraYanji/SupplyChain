import os
import re
import sys
import json
import base64
import requests
import textwrap
from datetime import datetime
from typing import List, Literal
from pydantic import BaseModel, ConfigDict, ValidationError
from openrouter import OpenRouter

# 1. Initialize API Clients from Environment Variables
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
MODEL = "openrouter/free"


if not OPENROUTER_API_KEY:
    print("[!] Error: OPENROUTER_API_KEY environment variable is not set.")
    sys.exit(1)

client = OpenRouter(api_key=OPENROUTER_API_KEY)


class MissingControlFinding(BaseModel):
    """One missing-control row - forces the model onto this exact shape/types."""
    model_config = ConfigDict(extra="forbid")

    id: str
    filename: str
    control: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    status: Literal["MISSING"]
    evidence: str
    action_required: str


class AuditFindings(BaseModel):
    """Top-level structured-output envelope (OpenAI/OpenRouter json_schema mode requires an object, not a bare array)."""
    model_config = ConfigDict(extra="forbid")

    findings: List[MissingControlFinding]


def load_benchmarks_from_json(file_path="security_benchmarks.json"):
    """Loads complete benchmarks (Stage, Severity, Control & Description) from a local JSON file."""
    if not os.path.exists(file_path):
        print(f"[!] Benchmark file not found at: {file_path}") #checks for the json file
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)  # 'data' is now our converted Python dictionary

        # FIX 1: Safely pull the actual benchmarks array/list out of the dictionary
        raw_benchmarks_list = data.get("benchmarks", [])

        # FIX 2: Define and calculate the total controls count directly from the list length
        total_controls_count = len(raw_benchmarks_list)

        formatted_list = []

        # FIX 1 (Continued): Enumerate over the actual parsed list variable!
        for index, item in enumerate(raw_benchmarks_list, start=1):
            control = item.get('control', 'Unknown Control')
            severity = item.get('severity', 'Medium').upper()
            description = item.get('description', '')

            # Create our clean tracking ID (SEC-01, SEC-02)
            control_id = f"SEC-{index:02d}"

            benchmark_line = f"- [ID: {control_id}] [SEVERITY: {severity}] {control}: {description}"
            formatted_list.append(benchmark_line)

        formatted_string = "\n".join(formatted_list)

        # Both variables are now perfectly defined and ready to return!
        return formatted_string, total_controls_count

    except Exception as e:
        print(f"[!] Error reading JSON benchmarks: {e}")
        return None


def get_pipeline_files_from_github(repo_owner, repo_name):
    """Fetches the text content of all YAML files from the remote GitHub directory."""
    target_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/.github/workflows"
    #target_url = f"https://api.github.com/repos/wrkode/virtrigaud/contents/.github/workflows"
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

    # FIXME: How is severity computed here? I think severity should be in the security benchmark not in the prompt.
    user_prompt =f"""
    Audit the following collection of YAML configuration files as a UNIFIED CI/CD pipeline network.
    
    CRITICAL COGNITIVE RULES TO PREVENT DUPLICATES:
    1. Do NOT evaluate files in isolation. Evaluate the repository as a whole ecosystem.
    2. A security control only belongs in its logical stage (e.g., Secret Scanning belongs in pre-build/test). 
    3. If a security control is successfully implemented in AT LEAST ONE relevant workflow file (e.g., secret scanning runs in ci.yml), then that control is considered COMPLIANT for the entire repository. Do NOT mark it as MISSING in other files like deploy.yml or build.yml.
    4. Only flag a control as MISSING if it is completely absent across the ENTIRE repository where it should logically be running.
    
    CRITICAL RULES FOR SECURITY IDENTIFIERS (IDs):
    - You must extract the unique identifier (e.g., SEC-01, SEC-02) from the [ID: ...] prefix of each benchmark listed below.
    - Match this ID exactly and populate it into the "id" field for every identified missing control. Do NOT invent new IDs.

    Return a unified flat JSON list of objects matching exactly this schema (Return ONLY raw JSON, no markdown backticks like ```json):
    [
      {{
        "id": "The extracted tracking ID from the benchmark (e.g., SEC-01)",
        "filename": "The primary file where this gap exists or where it should logically be fixed",
        "control": "Name of the security control",
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

    structured_response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "missing_security_controls",
            "strict": True,
            "schema": AuditFindings.model_json_schema(),
        },
    }

    def _send(with_structured_output):
        return client.chat.send(
            model=MODEL,  # This was pointed to "openrouter/free" or a single string
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,  # Low temperature keeps the structure clean and predictable
            response_format=structured_response_format if with_structured_output else None,
        )

    try:
        # Core OpenRouter cloud generation connection block
        try:
            response = _send(with_structured_output=True)
        except Exception:
            # Some models/providers on this route reject the response_format param entirely -
            # fall back to the free-text prompt, which the rest of the pipeline can still parse.
            response = _send(with_structured_output=False)

        raw_content = response.choices[0].message.content

        # If the model honored the schema it returns {"findings": [...]}; unwrap that back into
        # the flat findings array the rest of the pipeline (table/report) already expects.
        try:
            validated = AuditFindings.model_validate_json(raw_content)
            return json.dumps([finding.model_dump() for finding in validated.findings])
        except (ValidationError, json.JSONDecodeError, TypeError):
            return raw_content
    except Exception as e:
        return f"[!] OpenRouter Cloud Completion processing failed: {e}"

def parse_ai_json_array(raw_string):
    """Parses the AI's JSON array response, stripping a ```json ... ``` (or plain ``` ... ```)
    markdown fence first if the model added one despite being told not to."""
    cleaned = raw_string.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned[3:].lstrip()
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()
    return json.loads(cleaned)


# Column spec shared by the table body and the divider/title-box width calculation:
# (header label, JSON key, column width)
TABLE_COLUMNS = [
    ("Security ID", "id", 10),
    ("Security Control", "control", 18),
    ("Filename", "filename", 20),
    ("Severity", "severity", 10),
    ("Status", "status", 12),
    ("Evidence", "evidence", 30),
    ("Action Required", "action_required", 25),
]

TABLE_ROW_FMT = " | ".join("{:<%d}" % width for _, _, width in TABLE_COLUMNS) + " |"
TABLE_DIVIDER = "+" + "+".join("-" * (width + 2) for _, _, width in TABLE_COLUMNS) + "+"
TABLE_WIDTH = len(TABLE_DIVIDER)


def convert_json_to_fixed_table(json_string):
    try:
        audit_data = parse_ai_json_array(json_string)

        # Initialize the table with headers
        lines = [
            TABLE_DIVIDER,
            TABLE_ROW_FMT.format(*(label for label, _, _ in TABLE_COLUMNS)),
            TABLE_DIVIDER
        ]

        for item in audit_data:
            # Wrap long sentences smoothly inside their column text boundaries
            wrapped_cols = [
                textwrap.wrap(str(item.get(key, "N/A")), width=width) or [""]
                for _, key, width in TABLE_COLUMNS
            ]

            # Find the vertical line height needed for the current row
            max_rows = max(len(col) for col in wrapped_cols)

            # Construct the row line-by-line
            for i in range(max_rows):
                row_values = [col[i] if i < len(col) else "" for col in wrapped_cols]
                lines.append(TABLE_ROW_FMT.format(*row_values))

            lines.append(TABLE_DIVIDER)

        return "\n".join(lines)
    except Exception as e:
        return f"[!] Table conversion failed: {e}\n{json_string}"

def parse_github_repo(raw_input):
    """Extracts (owner, repo) from a GitHub URL, SSH remote, or "owner/repo" shorthand."""
    text = raw_input.strip()

    ssh_match = re.match(r"^git@github\.com:([^/]+)/([^/]+?)(\.git)?/?$", text)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)

    text = re.sub(r"^https?://(www\.)?github\.com/", "", text)
    text = text.strip("/")
    text = re.sub(r"\.git$", "", text)

    parts = text.split("/")
    if len(parts) >= 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    return None, None


if __name__ == "__main__":
    #Ask interactively for the target repository URL
    target_input = input(
        "Enter GitHub repo URL:"
    ).strip()
    owner, repo = parse_github_repo(target_input)

    if not owner or not repo:
        print(" Could not parse an owner/repo from that input.")
        sys.exit(1)

    # Extract benchmarks string from your clean JSON
    benchmarks, total_controls_count  = load_benchmarks_from_json("security_benchmarks.json")
    if not benchmarks:
        print("No security benchmarks found.")
        sys.exit(1)

    print(f" Loaded security checklist containing {total_controls_count} mandatory control rules.")

        # Pull target YAML definitions from GitHub contents endpoint
    workflows = get_pipeline_files_from_github(owner, repo)

    if not workflows:
        print("[*] No workflow configurations found to audit.")
        sys.exit(1)  # TODO: exit with message
    else:
        print(f"\n Found {len(workflows)} workflow file(s). Starting the Scan....")

        print(f"\n" + "-" * TABLE_WIDTH)
        print(f"SECURITY CONTROLS ON PIPELINE".center(TABLE_WIDTH))
        print("-" * TABLE_WIDTH)

        # Pass the complete dictionary of workflows straight to the batch function
        raw_ai_response = analyze_all_pipelines_batch(workflows, benchmarks)

        try:
            # 1. Parse the AI response to verify it's valid JSON
            raw_results = parse_ai_json_array(raw_ai_response)

            # 2. Filter the array to keep only rows where the status is MISSING
            filtered_results = [row for row in raw_results if row.get("status") == "MISSING"]

            # --- METRIC: Count Missing Controls Found ---
            missing_controls_count = len(filtered_results)

            # 3. Re-serialize back to a string and send to your existing formatter
            report_table = convert_json_to_fixed_table(raw_ai_response)
            print(report_table)

            # 4. Print metrics summary at the very bottom
            print("-" * TABLE_WIDTH)
            if missing_controls_count == 0:
                print(
                    f"AUDIT SUCCESS: 0 gaps found. All processed workflows comply with the security checklist.")
                sys.exit(0)
            else:
                print(
                    f"AUDIT ALERT: Found {missing_controls_count} missing security control gaps across your workflows!")
                print("-" * TABLE_WIDTH)
                # --- SAVE REPORT ONLY IF GAPS ARE FOUND ---
                folder_name = "Results"
                # Generate a timestamp like: 20260728_151458
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                os.makedirs(folder_name, exist_ok=True) #make the folder if doesnot exit

                report_filename = f"audit_report_{owner}_{repo}_{timestamp}.json"
                full_report_path = os.path.join(folder_name, report_filename)

                try:
                    with open(full_report_path, "w", encoding="utf-8") as f:
                        # Write the filtered list of missing controls as pretty-printed JSON
                        json.dump(filtered_results, f, indent=4)
                    print(f" Missing controls found! Detailed report saved to: {report_filename}")
                except Exception as file_err:
                    print(f" Warning: Could not write report file: {file_err}")

                print(
                    f"AUDIT ALERT: Found {missing_controls_count} missing security controls."
                )
                print("-" * TABLE_WIDTH)
                sys.exit(1)

            # TODO: there should be a way to store the report (json).(DONE)
            # XXX: Is it possible to provide some additional context to the user when some steps are missing?
            # XXX: Can we give IDs to controls? (done)
            # FIXME: when controls are missing return 1 as the resturn value of the script because the program fails.
        except Exception as json_err:
            # Fallback if the OpenRouter endpoint fails or returns plain text errors
            print(f"\n[!] Could not generate table dashboard. Raw engine response:")
            print(raw_ai_response)
            sys.exit(2)
            # FIXME: also here return 2