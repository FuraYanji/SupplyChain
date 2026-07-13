CI/CD Compliance Auditor
An automated Python tool that scans GitHub repositories, extracts CI/CD workflow configurations (.github/workflows/*.yml), and evaluates them against security benchmarks using open-weights AI models via OpenRouter.

Features
 - Extracts active GitHub pipeline configurations directly via the GitHub API.
 - Reviews parameters, permissions, and steps against predefined security controls.
 - Routes requests to openrouter/free for automatic load balancing across free models.
 - Displays the result in the terminal.

Installation
 - Install the required Python dependencies
   
Configuration
Set up your access tokens as environment variables in your terminal or development environment:

Bash
 - export OPENROUTER_API_KEY="your_openrouter_api_key_here"
 - export GITHUB_TOKEN="your_github_token_here"

How to Run the Script
Execute the script from your terminal or IDE:
Enter the target repository information when prompted: 
 - Enter GitHub Organization/Owner: octocat(example)
 - Enter Repository Name: Spoon-Knife(example)

## Testing
 
 - https://github.com/kyverno/kyverno/tree/main
 - https://github.com/nodejs/node
 - https://github.com/nginx/nginx
 - https://github.com/react/react
 - https://github.com/rust-lang/rust
 - https://github.com/anthropics/claude-code