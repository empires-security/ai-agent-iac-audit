# AI-Agent IAC Audit
An AI-powered agent for auditing Infrastructure-as-Code (IaC) templates against security best practices, compliance requirements, and custom rules.

## Overview

This tool uses AI models to analyze CloudFormation templates for security issues, compliance violations, and adherence to best practices. It provides comprehensive security analysis from multiple security perspectives and generates detailed reports with actionable remediation steps.

The analyzer connects to either a local Docker-based model (via Model Runner) or a remote SageMaker endpoint to process CloudFormation templates. This makes it suitable for both local development environments and integration into DevSecOps pipelines where larger models might be needed for complex template analysis.

## Features

- **Multi-persona analysis**: Evaluate templates from different security perspectives (Security Auditor, Data Protection Specialist, Network Security Expert)
- **Deep security analysis**: Detects issues related to IAM permissions, encryption, network exposure, and more
- **Compliance checking**: Validates against AWS Well-Architected Framework, ISO 27001, and ISO 42001 standards
- **CloudFormation parsing**: Full support for CloudFormation intrinsic functions and references
- **Flexible model integration**: Use local Docker models or call AWS SageMaker endpoints for larger templates
- **Detailed remediation**: Provides specific, actionable code fixes for identified issues
- **MCP/A2A protocol support**: Run as a server for integration with other tools and agents

## Installation

```bash
# Clone the repository
git clone https://github.com/empires-security/ai-agent-iac-audit.git
cd ai-agent-iac-audit

# Install dependencies
npm install
```

## Prerequisites

- Node.js (v18 or higher)
- Docker (for local model execution via Model Runner)
- AWS credentials (if using SageMaker endpoints for analysis)

## Usage

### Basic Usage

```bash
# Analyze a template with default settings (uses local Docker model)
node analyzer.js examples/template.yaml

# Analyze with custom rules and output
node analyzer.js --rules examples/custom-rules.json --output results.json examples/template.yaml

# Use SageMaker endpoint for analysis (for larger templates or in CI/CD pipelines)
node analyzer.js --sagemaker examples/template.yaml
```

### Advanced Options

```bash
# Run as a server on port 8080
node analyzer.js --server --port 8080

# Single-persona analysis (faster)
node analyzer.js --single-persona examples/template.yaml

# Multi-persona analysis (more comprehensive)
node analyzer.js --multi-persona examples/template.yaml
```

### Command Line Options

```
OPTIONS:
  --rules <file>         Path to rules JSON file (default: ./cloudformation-standards.json)
  --output <file>        Path to output file (default: ./analysis-results.json)
  --sagemaker            Use SageMaker endpoint for analysis instead of Docker
  --docker               Use local Docker Model Runner for analysis (default)
  --single-persona       Use single persona analysis (faster)
  --multi-persona        Use multi-persona analysis for comprehensive results (default)
  --server               Run as MCP/A2A protocol server
  --port <number>        Port for server mode (default: 3000)
  --help, -h             Show this help message
```

## Example Templates

The repository includes several example CloudFormation templates in the `/examples` directory:

- Simple deployment patterns
- Three-tier architecture
- Event-driven architecture
- Microservices architecture
- Templates with common security issues

## Rules Configuration

Custom rules can be defined in a JSON file. An example rules file is provided at `./cloudformation-standards.json`.

The rules file structure:

```json
{
  "rules": [
    {
      "id": "CFN-SEC-1",
      "name": "S3 Bucket Encryption",
      "description": "S3 buckets should have encryption enabled",
      "severity": "HIGH",
      "resource_types": ["AWS::S3::Bucket"],
      "compliance": ["ISO-27001-A.10", "AWS-WA-SEC-7"]
    },
    // More rules...
  ]
}
```

## API Server Mode (MCP/A2A Protocol)

The analyzer can run as a server that implements the Model Communication Protocol (MCP) and Agent-to-Agent (A2A) protocol standards, making it compatible with other MCP/A2A-enabled tools and agents.

Start the server with:

```bash
node analyzer.js --server --port 8080
```

### Available Endpoints

- `/analyze` - Primary endpoint for CloudFormation template analysis
- `/health` - Health check endpoint for monitoring
- `/a2a/query` - A2A protocol endpoint supporting various query types

Example request to `/analyze`:

```json
{
  "templateContent": "AWSTemplateFormatVersion: '2010-09-09'...",
  "rulesContent": { "rules": [...] },
  "options": {
    "useSageMaker": false,
    "multiPersona": true
  }
}
```

## Environment Variables

You can configure the tool using environment variables:

```
MODEL_RUNNER_HOST=localhost
MODEL_RUNNER_PORT=12434
MODEL_NAME=ai/deepseek-r1-distill-llama:8B-Q4_K_M
USE_SAGEMAKER=false
SAGEMAKER_ENDPOINT=your-endpoint
SAGEMAKER_REGION=us-east-1
ENABLE_MULTI_PERSONA=true
MAX_TOKENS=8192
TEMPERATURE=0.1
```

## Sample Output

The tool generates detailed analysis output in JSON format:

```json
{
  "template_name": "my-template.yaml",
  "findings": [
    {
      "rule_id": "CFN-SEC-1",
      "severity": "HIGH",
      "resource": "MyS3Bucket",
      "description": "S3 bucket missing encryption configuration",
      "impact": "Data stored in this bucket is not encrypted at rest",
      "remediation": "Add BucketEncryption property with appropriate encryption configuration",
      "best_practice_context": "AWS Well-Architected Framework recommends encrypting data at rest"
    }
  ],
  "compliant_rules": ["CFN-SEC-2", "CFN-SEC-3"],
  "general_best_practices": {
    "compliant": ["Resource tagging", "Proper stack parameters"],
    "non_compliant": ["Missing descriptions", "Overly permissive security groups"]
  },
  "summary": {
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 2,
    "low_count": 3,
    "overall_risk": "HIGH",
    "recommendations": "Enable encryption for S3 buckets and restrict security group access"
  }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- AWS CloudFormation documentation
- AWS Well-Architected Framework
- ISO 27001 and ISO 42001 standards
- Docker Model Runner project
