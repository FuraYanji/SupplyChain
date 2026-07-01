import os
import sys
import yaml

def get_workflow_directory():
    # 1. Check if the user forgot to pass the repository path
    if len(sys.argv) < 2:
        print("Error: Please provide the path to the repository.")
        print("Usage: python Checklist.py <path_to_cloned_repo>")
        sys.exit(1)

    # 2. Grab the path passed by the user
    repo_path = sys.argv[1]

    # 3. Combine that path with the standard GitHub Actions directory structure
    workflow_dir = os.path.join(repo_path, ".github", "workflows")

    # 4. Safely verify if that folder actually exists
    if not os.path.exists(workflow_dir):
        print(
            f" Warning: The directory '{workflow_dir}' does not exist or has no GitHub workflows."
        )
        return None

    print(f"Target workflow directory found: {workflow_dir}")
    return workflow_dir

def extract_pipeline_controls(workflow_dir):
    extracted_data = []

    # Loop through every file in the workflows directory
    for filename in os.listdir(workflow_dir):
        # Make sure we are only reading YAML files
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            file_path = os.path.join(workflow_dir, filename)
            print(f"Parsing file: {filename}")

            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    # Load the YAML content into a Python dictionary
                    data = yaml.safe_load(file)

                    # Safely dig into the 'jobs' block
                    if data and "jobs" in data:
                        for job_name, job_data in data["jobs"].items():
                            # Safely dig into the 'steps' block of each job
                            if "steps" in job_data and isinstance(
                                job_data["steps"], list
                            ):
                                for step in job_data["steps"]:
                                    # Grab marketplace actions (uses:)
                                    if "uses" in step:
                                        extracted_data.append(
                                            f"[{filename}] Uses: {step['uses']}"
                                        )
                                    # Grab custom CLI commands (run:)
                                    if "run" in step:
                                        extracted_data.append(
                                            f"[{filename}] Runs CLI command: {step['run'].strip()}"
                                        )

                                    # result = Ollama.ask("", step, sync)
            except Exception as e:
                print(f"Error reading {filename}: {e}")

    return extracted_data


# --- Main Execution Block ---
if __name__ == "__main__":
    target_dir = get_workflow_directory()

    if target_dir:
        # Step 2: Extract the controls
        findings = extract_pipeline_controls(target_dir)

        print("\n--- Extracted Pipeline Step Data ---")
        for finding in findings:
            print(finding)

        # NEW CODE: Save these findings to the Results folder
        results_folder = "./Results"
        output_file_path = os.path.join(results_folder, "raw_findings.txt")

        # Open the file in write ('w') mode
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write("=== RAW PIPELINE FINDINGS ===\n")
            for finding in findings:
                f.write(f"{finding}\n")

        print(f"\nSuccessfully saved raw steps to: {output_file_path}")

