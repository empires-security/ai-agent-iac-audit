const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const { SageMakerRuntimeClient, InvokeEndpointCommand } = require('@aws-sdk/client-sagemaker-runtime');

/**
 * CloudFormation Security Analyzer
 * 
 * This tool analyzes CloudFormation templates against security best practices,
 * compliance requirements, and custom rules.
 * 
 * Features:
 * - Multi-persona analysis from different security perspectives
 * - Support for CloudFormation intrinsic functions
 * - Integration with Docker Model Runner or SageMaker endpoints
 * - Compliance with AWS Well-Architected, ISO 27001, ISO 42001
 */

// Configuration - can be overridden through environment variables or CLI args
const config = {
  // Model configuration
  MODEL_RUNNER_HOST: process.env.MODEL_RUNNER_HOST || 'localhost',
  MODEL_RUNNER_PORT: process.env.MODEL_RUNNER_PORT || '12434',
  MODEL_NAME: process.env.MODEL_NAME || 'ai/deepseek-r1-distill-llama:8B-Q4_K_M',
  MODEL_CONTEXT_SIZE: parseInt(process.env.MODEL_CONTEXT_SIZE || '16384'),
  USE_SAGEMAKER: process.env.USE_SAGEMAKER === 'true' || false,
  SAGEMAKER_ENDPOINT: process.env.SAGEMAKER_ENDPOINT || '',
  SAGEMAKER_REGION: process.env.SAGEMAKER_REGION || 'us-east-1',
  
  // Analysis configuration
  ENABLE_MULTI_PERSONA: process.env.ENABLE_MULTI_PERSONA !== 'false',
  MAX_TOKENS: parseInt(process.env.MAX_TOKENS || '8192'),
  TEMPERATURE: parseFloat(process.env.TEMPERATURE || '0.1'),
  
  // Default rules file if not provided
  DEFAULT_RULES_PATH: path.resolve(__dirname, './cloudformation-standards.json'),
  
  // Output configuration
  OUTPUT_FORMAT: process.env.OUTPUT_FORMAT || 'json' // 'json' or 'text'
};

/**
 * Load and parse the rules file
 * @param {string} rulesPath - Path to rules JSON file
 * @returns {Object} - Parsed rules
 */
async function loadRules(rulesPath) {
  try {
    const rulesContent = await fs.readFile(rulesPath, 'utf8');
    return JSON.parse(rulesContent);
  } catch (error) {
    console.error(`Error loading rules file from ${rulesPath}:`, error.message);
    throw error;
  }
}

/**
 * Generate a comprehensive system prompt for CloudFormation analysis
 * @param {Object} rules - Rules object
 * @param {string} persona - Security persona perspective for the analysis
 * @returns {string} - System prompt for the LLM
 */
function generateSystemPrompt(rules, persona = 'Security Auditor') {
  // Convert rules to a string representation for the prompt
  const rulesStr = JSON.stringify(rules, null, 2);

  // Base prompt with detailed instructions
  const basePrompt = `You are an AWS CloudFormation Security Expert specializing in compliance and security analysis.

TASK:
Analyze CloudFormation templates for security issues, compliance violations, and best practices using the following step-by-step process:

STEP 1: RESOURCE INVENTORY
- Identify and list all resources in the template
- Note each resource's type and key properties
- Group resources by category (compute, storage, network, IAM, etc.)

STEP 2: RULE EVALUATION
- For each rule provided below, methodically:
  * Identify which resources the rule applies to
  * Check if each resource complies with the rule
  * Document any violations with specific details

STEP 3: BEST PRACTICE ASSESSMENT
- Review resources against AWS Well-Architected Framework security pillars
- Check for common security misconfigurations
- Identify any deviations from general CloudFormation best practices

STEP 4: VULNERABILITY ANALYSIS
- For each potential issue found:
  * Determine the exact security implications
  * Assess potential attack vectors
  * Evaluate business impact of exploitation
  * Assign appropriate severity level based on impact

STEP 5: REMEDIATION PLANNING
- For each issue:
  * Formulate precise code fixes that follow AWS best practices
  * Ensure remediation addresses the root cause
  * Verify the fix doesn't introduce new issues
  * Explain why the fix aligns with security principles

RULES TO CHECK:
${rulesStr}

ADDITIONAL CLOUDFORMATION BEST PRACTICES TO CHECK:
Even if not explicitly mentioned in the rules above, check for these critical CloudFormation security best practices:

1. Sensitive Information Management:
   - No embedded credentials or secrets in templates
   - Use of AWS Secrets Manager or Systems Manager Parameter Store for sensitive data
   - Use of dynamic references for sensitive information

2. IAM Security:
   - Principle of least privilege in IAM policies
   - No wildcard permissions (*) in IAM policies
   - IAM roles follow proper naming conventions and include clear descriptions
   - Service roles used for CloudFormation stack operations

3. Data Security:
   - Encryption enabled for data at rest (S3, RDS, EBS, etc.)
   - Encryption in transit configured where applicable
   - Public access blocked where not required
   - Proper access logging enabled

4. Networking:
   - No overly permissive security groups (0.0.0.0/0)
   - Proper subnet configuration for multi-tier applications
   - Use of private subnets for sensitive resources

5. Infrastructure Protection:
   - Termination protection enabled for critical stacks
   - Deletion policies configured appropriately
   - Stack policies in place for critical resources

6. Resource Configuration:
   - Resources properly tagged
   - Latest AMIs and software versions used
   - CloudWatch monitoring and alerting configured

7. AI-Specific (ISO 42001) Requirements:
   - Appropriate data governance controls
   - Mechanisms for AI risk assessment
   - AI impact evaluation measures
   - Transparency and explainability features
   - AI system monitoring and evaluation

IMPORTANT: When analyzing the template, be extremely careful to verify that properties you mention belong to the correct resource types. For example:
- MasterUserPassword only applies to database resources like RDS instances, not to Lambda functions
- BucketEncryption only applies to S3 buckets
- SecurityGroupIngress only applies to security groups

HANDLING CLOUDFORMATION INTRINSIC FUNCTIONS (CRITICAL):

When analyzing CloudFormation templates with intrinsic functions (!Ref, !GetAtt, !Sub, etc.):

1. PARAMETERS AND REFS:
   - For !Ref to a parameter, check the parameter's allowed values or constraints
   - For !Ref to a resource, analyze the security implications of the dependency
   - Example: "!Ref MyBucket" should be treated as if it was the actual S3 bucket name

2. GETATT FUNCTIONS:
   - For !GetAtt X.Y, determine what resource attribute is being accessed
   - Example: "!GetAtt MyInstance.PrivateIp" provides a private IP address

3. SUB FUNCTIONS:
   - For !Sub strings, identify variables that will be substituted
   - Example: "!Sub '\${AWS::Region}-myapp'" would resolve to the region plus "-myapp"

4. JOIN AND SELECT:
   - !Join combines elements with a delimiter
   - !Select chooses an element from a list
   - Always assume the most security-critical possible value

5. ANALYSIS STRATEGY:
   - Evaluate both the best and worst-case values for each function
   - For IAM permissions, assume the broadest possible scope
   - For security groups, assume the most permissive interpretation
   - Flag any intrinsic function that references an external value or non-hardcoded input

COMPLIANCE STANDARDS TO CONSIDER:
1. ISO 27001 - Information Security Management
   - Access controls (A.9)
   - Cryptography (A.10)
   - Operations security (A.12)
   - Communications security (A.13)

2. ISO 42001 - Artificial Intelligence Management Systems
   - AI governance
   - Risk management
   - Data handling practices
   - Transparency measures

3. AWS Well-Architected Framework
   - Security pillar
   - Operational Excellence pillar
   - Reliability pillar
   - Performance Efficiency pillar
   - Cost Optimization pillar
   - Sustainability pillar

OUTPUT FORMAT - EXTREMELY IMPORTANT:
Your response MUST be valid JSON in the following format. Do not include any commentary, explanations, or text outside of this JSON structure:

{
  "template_name": "Name of the template",
  "findings": [
    {
      "rule_id": "RULE-ID or CUSTOM-ID for custom findings",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "resource": "ResourceId in template",
      "description": "Clear description of the issue",
      "impact": "Detailed explanation of security impact and business risk",
      "remediation": "Specific, actionable code fix with example",
      "best_practice_context": "Explanation of why this is important based on AWS Well-Architected Framework or other standards"
    }
  ],
  "compliant_rules": ["List of rule IDs that passed"],
  "general_best_practices": {
    "compliant": ["List of general best practices that are properly implemented"],
    "non_compliant": ["List of general best practices that are violated"]
  },
  "summary": {
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "overall_risk": "HIGH|MEDIUM|LOW",
    "recommendations": "Overall recommendations for improving template security"
  }
}

DO NOT include any text outside of this JSON structure. Your entire response must be valid, parseable JSON.`;

  // Add persona-specific focus
  switch (persona) {
    case 'Data Protection Specialist':
      return `${basePrompt}\n\nYou are specifically analyzing this template as a Data Protection Specialist. Focus especially on issues related to data security, encryption, access controls, and privacy. Pay special attention to:
- Data encryption at rest and in transit
- Access control mechanisms for data resources
- Data lifecycle management
- Personal data handling practices
- Privacy-by-design implementation`;
      
    case 'Network Security Expert':
      return `${basePrompt}\n\nYou are specifically analyzing this template as a Network Security Expert. Focus especially on issues related to network configuration, connectivity, and exposure. Pay special attention to:
- Security group configurations
- Network access controls and restrictions
- VPC design and subnet configurations
- Network traffic filtering
- Exposure of resources to public networks`;
      
    case 'Compliance Auditor':
      return `${basePrompt}\n\nYou are specifically analyzing this template as a Compliance Auditor. Focus especially on issues related to organizational standards compliance, regulatory requirements, and governance. Pay special attention to:
- Alignment with ISO 27001 and ISO 42001 requirements
- Tagging compliance for cost allocation
- Audit trail and monitoring configurations
- Regulatory requirements for various industries
- Governance controls and documentation`;
      
    default: // Security Auditor (general)
      return basePrompt;
  }
}

/**
 * Extract JSON from the LLM response or create a structured object from text
 * @param {string} text - LLM response text
 * @returns {Object} - Parsed JSON or structured object created from text
 */
function extractJsonFromText(text) {
  try {
    // Try direct parsing first
    try {
      return JSON.parse(text);
    } catch (e) {
      // Look for JSON-like structures with pattern matching
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try {
          return JSON.parse(jsonMatch[0]);
        } catch (innerError) {
          // Try to clean up common JSON issues
          let cleanedJson = jsonMatch[0]
            // Fix trailing commas in objects
            .replace(/,(\s*[\}\]])/g, '$1')
            // Fix missing quotes around property names
            .replace(/([{,]\s*)([a-zA-Z0-9_]+)(\s*:)/g, '$1"$2"$3');

          try {
            return JSON.parse(cleanedJson);
          } catch (e) {
            console.warn('Failed to parse JSON after cleanup:', e.message);
            // Fall through to text parsing
          }
        }
      }
      
      // If no JSON found, convert text analysis to JSON structure
      console.log('No JSON found in response, converting text to structured format');
      return convertTextToStructuredFormat(text);
    }
  } catch (error) {
    console.error('Error extracting JSON:', error.message);
    return convertTextToStructuredFormat(text);
  }
}

/**
 * Convert text analysis to a structured format
 * @param {string} text - Text analysis from LLM
 * @returns {Object} - Structured object with findings
 */
function convertTextToStructuredFormat(text) {
  const paragraphs = text.split('\n\n').filter(p => p.trim().length > 0);
  
  // Extract sections from the text based on common patterns
  const sections = [];
  let currentSection = { title: 'Overview', content: [] };
  
  for (const paragraph of paragraphs) {
    // Check if paragraph starts a new section (###, ##, or other common section markers)
    if (paragraph.startsWith('###') || paragraph.startsWith('##') || 
        paragraph.match(/^[0-9]+\.\s+\*\*[^*]+\*\*/) ||
        paragraph.match(/^[A-Z][A-Za-z\s]+:$/)) {
      
      // Save the previous section if it has content
      if (currentSection.content.length > 0) {
        sections.push(currentSection);
      }
      
      // Extract section title
      let title = paragraph;
      if (paragraph.startsWith('###')) {
        title = paragraph.replace(/^###\s+/, '').replace(/\*\*/g, '');
      } else if (paragraph.startsWith('##')) {
        title = paragraph.replace(/^##\s+/, '').replace(/\*\*/g, '');
      } else if (paragraph.match(/^[0-9]+\.\s+\*\*[^*]+\*\*/)) {
        title = paragraph.replace(/^[0-9]+\.\s+\*\*([^*]+)\*\*.*/, '$1');
      } else if (paragraph.match(/^[A-Z][A-Za-z\s]+:$/)) {
        title = paragraph.replace(/:$/, '');
      }
      
      currentSection = { title, content: [] };
    } else {
      // Add paragraph to current section
      currentSection.content.push(paragraph);
    }
  }
  
  // Add the last section
  if (currentSection.content.length > 0) {
    sections.push(currentSection);
  }
  
  // Extract findings from sections
  const findings = [];
  let ruleIdCounter = 1;
  
  for (const section of sections) {
    // Skip sections that are likely not findings
    if (['Overview', 'Summary', 'Conclusion'].includes(section.title)) {
      continue;
    }
    
    // Determine severity based on keywords in content
    let severity = 'MEDIUM';
    const contentText = section.content.join(' ').toLowerCase();
    if (contentText.includes('critical') || contentText.includes('severe') || 
        contentText.includes('high risk') || contentText.includes('vulnerability')) {
      severity = 'HIGH';
    } else if (contentText.includes('minor') || contentText.includes('low risk') ||
               contentText.includes('suggestion')) {
      severity = 'LOW';
    }
    
    // Extract resources mentioned
    const resourceMatches = contentText.match(/(\w+)\s+(instance|bucket|security group|role|database|vpc|subnet|gateway)/gi);
    const resources = resourceMatches 
      ? [...new Set(resourceMatches.map(m => m.replace(/\s+(instance|bucket|security group|role|database|vpc|subnet|gateway)/i, '')))]
      : ['global'];
    
    for (const resource of resources) {
      findings.push({
        rule_id: `CUSTOM-TEXT-${ruleIdCounter.toString().padStart(3, '0')}`,
        severity,
        resource,
        description: section.title,
        impact: section.content.slice(0, 1).join(' '),
        remediation: "See analysis in the text response.",
        best_practice_context: "See analysis in the text response."
      });
      ruleIdCounter++;
    }
  }
  
  // Calculate counts by severity
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity === 'LOW').length;
  
  // Determine overall risk
  let overallRisk = 'LOW';
  if (criticalCount > 0) {
    overallRisk = 'CRITICAL';
  } else if (highCount > 0) {
    overallRisk = 'HIGH';
  } else if (mediumCount > 0) {
    overallRisk = 'MEDIUM';
  }
  
  // Create recommendations from conclusion section
  const conclusionSection = sections.find(s => s.title.toLowerCase().includes('conclusion') || 
                                             s.title.toLowerCase().includes('summary'));
  const recommendations = conclusionSection 
    ? conclusionSection.content.join('\n\n')
    : "See the full text analysis for detailed recommendations.";
  
  // Build structured response
  return {
    template_name: "Template analyzed from text response",
    findings,
    compliant_rules: [],
    general_best_practices: {
      compliant: [],
      non_compliant: []
    },
    summary: {
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      low_count: lowCount,
      overall_risk: overallRisk,
      recommendations
    },
    text_analysis: true,
    raw_text: text.substring(0, 5000) // Include first 5000 chars for reference
  };
}

/**
 * Invoke Docker Model Runner for analysis
 * @param {string} systemPrompt - System prompt for the model
 * @param {string} userPrompt - User prompt containing the template to analyze
 * @returns {Promise<Object>} - Analysis results
 */
async function invokeDockerModelRunner(systemPrompt, userPrompt) {
  const modelRunnerUrl = `http://${config.MODEL_RUNNER_HOST}:${config.MODEL_RUNNER_PORT}/engines/v1/chat/completions`;
  
  // Check if Docker Model Runner is available
  try {
    await axios.get(`http://${config.MODEL_RUNNER_HOST}:${config.MODEL_RUNNER_PORT}/health`);
  } catch (error) {
    throw new Error(`Docker Model Runner not available at ${modelRunnerUrl}. Error: ${error.message}`);
  }
  
  // Prepare request payload
  const payload = {
    model: config.MODEL_NAME,
    messages: [
      {
        role: "system",
        content: systemPrompt
      },
      {
        role: "user",
        content: userPrompt
      }
    ],
    temperature: config.TEMPERATURE,
    max_tokens: config.MAX_TOKENS,
    context_size: config.MODEL_CONTEXT_SIZE
  };
  
  try {
    // Make request to Docker Model Runner
    const response = await axios.post(modelRunnerUrl, payload, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 180000 // 3-minute timeout for larger templates
    });
    
    // Extract response content
    if (response.data.choices && response.data.choices.length > 0) {
      return response.data.choices[0].message.content;
    } else {
      throw new Error('Unexpected response format from Docker Model Runner');
    }
  } catch (error) {
    console.error('Error invoking Docker Model Runner:', error);
    throw error;
  }
}

/**
 * Invoke SageMaker endpoint for analysis
 * @param {string} systemPrompt - System prompt for the model
 * @param {string} userPrompt - User prompt containing the template to analyze
 * @returns {Promise<Object>} - Analysis results
 */
async function invokeSageMakerEndpoint(systemPrompt, userPrompt) {
  // Initialize SageMaker client
  const client = new SageMakerRuntimeClient({ 
    region: config.SAGEMAKER_REGION
  });
  
  // Format the input for the model
  const input = {
    messages: [
      {
        role: "system",
        content: systemPrompt
      },
      {
        role: "user",
        content: userPrompt
      }
    ],
    temperature: config.TEMPERATURE,
    max_tokens: config.MAX_TOKENS,
    context_size: config.MODEL_CONTEXT_SIZE
  };
  
  // Create the command
  const command = new InvokeEndpointCommand({
    EndpointName: config.SAGEMAKER_ENDPOINT,
    ContentType: 'application/json',
    Body: JSON.stringify(input)
  });
  
  try {
    // Send the request to SageMaker
    const response = await client.send(command);
    
    // Parse the response
    const responseBody = JSON.parse(Buffer.from(response.Body).toString('utf8'));
    
    if (responseBody.generation) {
      return responseBody.generation;
    } else if (responseBody.choices && responseBody.choices.length > 0) {
      return responseBody.choices[0].message.content;
    } else {
      throw new Error('Unexpected response format from SageMaker endpoint');
    }
  } catch (error) {
    console.error('Error invoking SageMaker endpoint:', error);
    throw error;
  }
}

/**
 * Run a single analysis pass
 * @param {string} templatePath - Path to CloudFormation template
 * @param {string} templateContent - Content of CloudFormation template
 * @param {Object} rules - Rules object
 * @param {string} persona - Security persona for this analysis
 * @returns {Promise<Object>} - Analysis results
 */
async function runAnalysisPass(templatePath, templateContent, rules, persona) {
  const templateName = path.basename(templatePath);
  
  // Generate prompts
  const systemPrompt = generateSystemPrompt(rules, persona);
  const userPrompt = `Analyze this CloudFormation template named "${templateName}":

IMPORTANT NOTES ABOUT CLOUDFORMATION:
1. This template may contain CloudFormation intrinsic functions like !Ref, !GetAtt, !Sub, etc.
2. These are placeholders that get resolved during deployment:
   - !Ref X refers to either a parameter value or resource created in the template
   - !GetAtt X.Y gets attribute Y from resource X
   - !Sub replaces \${VarName} in strings with actual values
3. When analyzing security, consider what these references COULD be at runtime
4. Focus on identifying security issues even with unresolved references
5. For IAM permissions and security groups, analyze for overly permissive settings

TEMPLATE CONTENT:
${templateContent}`;
  
  console.log(`Running analysis as ${persona}...`);
  
  try {
    // Choose invocation method based on configuration
    let responseText;
    if (config.USE_SAGEMAKER) {
      responseText = await invokeSageMakerEndpoint(systemPrompt, userPrompt);
    } else {
      responseText = await invokeDockerModelRunner(systemPrompt, userPrompt);
    }
    
    // Extract JSON from response
    const analysisResults = extractJsonFromText(responseText);
    
    if (!analysisResults) {
      // If we couldn't parse JSON, try to extract some structured data
      console.warn(`Failed to extract valid JSON results from ${persona} analysis`);
      
      // Create a basic structure with the raw response
      return {
        template_name: templateName,
        findings: [],
        compliant_rules: [],
        general_best_practices: {
          compliant: [],
          non_compliant: []
        },
        summary: {
          critical_count: 0,
          high_count: 0,
          medium_count: 0,
          low_count: 0,
          overall_risk: "UNKNOWN",
          recommendations: "Could not extract structured recommendations."
        },
        raw_response: responseText.substring(0, 1000) + '...' // First 1000 chars for debugging
      };
    }
    
    return analysisResults;
  } catch (error) {
    console.error(`Error in ${persona} analysis:`, error.message);
    
    // Return a basic structure instead of throwing
    return {
      template_name: templateName,
      error: `Analysis as ${persona} failed: ${error.message}`,
      findings: [],
      compliant_rules: [],
      general_best_practices: {
        compliant: [],
        non_compliant: []
      },
      summary: {
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        overall_risk: "UNKNOWN",
        recommendations: "Analysis failed."
      }
    };
  }
}

/**
 * Deduplicate findings based on rule_id and resource
 * @param {Array} findings - Array of findings from all analysis passes
 * @returns {Array} - Deduplicated findings
 */
function deduplicateFindings(findings) {
  const findingMap = new Map();
  
  findings.forEach(finding => {
    const key = `${finding.rule_id}-${finding.resource}`;
    
    if (findingMap.has(key)) {
      // Choose the more detailed description and impact
      const existingFinding = findingMap.get(key);
      
      if (finding.description.length > existingFinding.description.length) {
        existingFinding.description = finding.description;
      }
      
      if (finding.impact.length > existingFinding.impact.length) {
        existingFinding.impact = finding.impact;
      }
      
      if (finding.remediation.length > existingFinding.remediation.length) {
        existingFinding.remediation = finding.remediation;
      }
      
      if (finding.best_practice_context.length > existingFinding.best_practice_context.length) {
        existingFinding.best_practice_context = finding.best_practice_context;
      }
    } else {
      findingMap.set(key, finding);
    }
  });
  
  return Array.from(findingMap.values());
}

/**
 * Consolidate results from multiple analysis passes
 * @param {Array} passes - Results from all analysis passes
 * @returns {Object} - Consolidated results
 */
function consolidateResults(passes, templateName) {
  if (passes.length === 0) {
    return {
      template_name: templateName,
      error: "All analysis passes failed"
    };
  }
  
  // Initialize consolidated results
  const consolidated = {
    template_name: templateName,
    findings: [],
    compliant_rules: [],
    general_best_practices: {
      compliant: [],
      non_compliant: []
    },
    summary: {
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      overall_risk: "LOW",
      recommendations: ""
    }
  };
  
  // Collect findings from all passes
  const allFindings = [];
  passes.forEach(pass => {
    if (pass.findings && Array.isArray(pass.findings)) {
      allFindings.push(...pass.findings);
    }
  });
  
  // Deduplicate findings
  consolidated.findings = deduplicateFindings(allFindings);
  
  // Combine compliant rules
  const compliantRulesSet = new Set();
  passes.forEach(pass => {
    if (pass.compliant_rules && Array.isArray(pass.compliant_rules)) {
      pass.compliant_rules.forEach(rule => compliantRulesSet.add(rule));
    }
  });
  consolidated.compliant_rules = Array.from(compliantRulesSet);
  
  // Combine best practices
  const compliantPracticesSet = new Set();
  const nonCompliantPracticesSet = new Set();
  
  passes.forEach(pass => {
    if (pass.general_best_practices) {
      if (pass.general_best_practices.compliant && Array.isArray(pass.general_best_practices.compliant)) {
        pass.general_best_practices.compliant.forEach(practice => compliantPracticesSet.add(practice));
      }
      
      if (pass.general_best_practices.non_compliant && Array.isArray(pass.general_best_practices.non_compliant)) {
        pass.general_best_practices.non_compliant.forEach(practice => nonCompliantPracticesSet.add(practice));
      }
    }
  });
  
  consolidated.general_best_practices.compliant = Array.from(compliantPracticesSet);
  consolidated.general_best_practices.non_compliant = Array.from(nonCompliantPracticesSet);
  
  // Update severity counts
  consolidated.findings.forEach(finding => {
    switch (finding.severity) {
      case 'CRITICAL':
        consolidated.summary.critical_count++;
        break;
      case 'HIGH':
        consolidated.summary.high_count++;
        break;
      case 'MEDIUM':
        consolidated.summary.medium_count++;
        break;
      case 'LOW':
        consolidated.summary.low_count++;
        break;
    }
  });
  
  // Determine overall risk
  if (consolidated.summary.critical_count > 0) {
    consolidated.summary.overall_risk = "CRITICAL";
  } else if (consolidated.summary.high_count > 0) {
    consolidated.summary.overall_risk = "HIGH";
  } else if (consolidated.summary.medium_count > 0) {
    consolidated.summary.overall_risk = "MEDIUM";
  }
  
  // Use recommendations from first pass
  if (passes.length > 0 && passes[0].summary && passes[0].summary.recommendations) {
    consolidated.summary.recommendations = passes[0].summary.recommendations;
  }
  
  return consolidated;
}

/**
 * Generate human-readable summary report
 * @param {Object} results - Analysis results
 * @returns {string} - Summary report
 */
function generateSummaryReport(results) {
  let report = '========= CLOUDFORMATION COMPLIANCE REPORT =========\n\n';
  report += `Template: ${results.template_name}\n\n`;
  
  if (results.error) {
    report += `ERROR: ${results.error}\n`;
    return report;
  }
  
  // Summary section
  report += `SUMMARY:\n`;
  report += `- Critical issues: ${results.summary.critical_count}\n`;
  report += `- High issues: ${results.summary.high_count}\n`;
  report += `- Medium issues: ${results.summary.medium_count}\n`;
  report += `- Low issues: ${results.summary.low_count}\n`;
  report += `- Overall risk: ${results.summary.overall_risk}\n\n`;
  
  // Critical and high findings
  const criticalAndHighFindings = results.findings.filter(f => 
    f.severity === 'CRITICAL' || f.severity === 'HIGH'
  );
  
  if (criticalAndHighFindings.length > 0) {
    report += `CRITICAL AND HIGH PRIORITY ISSUES:\n`;
    criticalAndHighFindings.forEach(finding => {
      report += `[${finding.severity}] ${finding.rule_id}: ${finding.resource}\n`;
      report += `  - ${finding.description}\n`;
      report += `  - Impact: ${finding.impact}\n`;
      report += `  - Remediation: ${finding.remediation}\n\n`;
    });
  }
  
  // Non-compliant best practices
  if (results.general_best_practices.non_compliant.length > 0) {
    report += `NON-COMPLIANT BEST PRACTICES:\n`;
    results.general_best_practices.non_compliant.forEach(practice => {
      report += `- ${practice}\n`;
    });
    report += '\n';
  }
  
  // Recommendations
  if (results.summary.recommendations) {
    report += `RECOMMENDATIONS:\n${results.summary.recommendations}\n\n`;
  }
  
  report += '================================================\n';
  return report;
}

/**
 * Main analysis function
 * @param {string} templatePath - Path to CloudFormation template
 * @param {string} rulesPath - Path to rules JSON file
 * @returns {Promise<Object>} - Analysis results
 */
async function analyzeTemplate(templatePath, rulesPath) {
  try {
    // Load template and rules
    console.log(`Reading template from: ${templatePath}`);
    const templateContent = await fs.readFile(templatePath, 'utf8');
    const templateName = path.basename(templatePath);
    
    console.log(`Loading rules from: ${rulesPath}`);
    const rules = await loadRules(rulesPath);
    
    // Define security personas for multi-persona analysis
    const personas = [
      'Security Auditor', 
      'Data Protection Specialist',
      'Network Security Expert'
    ];
    
    // Run analysis passes
    const passes = [];
    
    if (config.ENABLE_MULTI_PERSONA) {
      // Multi-persona analysis
      for (const persona of personas) {
        try {
          const results = await runAnalysisPass(templatePath, templateContent, rules, persona);
          passes.push(results);
        } catch (error) {
          console.warn(`Error in ${persona} analysis pass:`, error.message);
        }
      }
    } else {
      // Single-persona analysis
      try {
        const results = await runAnalysisPass(templatePath, templateContent, rules, 'Security Auditor');
        passes.push(results);
      } catch (error) {
        console.error('Error in analysis:', error.message);
      }
    }
    
    // Consolidate results
    console.log(`Consolidating results...`);
    const consolidated = consolidateResults(passes, templateName);
    
    // Add basic template metadata
    consolidated.template_metadata = {
      template_size: templateContent.length,
      template_format: templateContent.trim().startsWith('{') ? 'json' : 'yaml',
      template_name: templateName
    };

    return consolidated;
  } catch (error) {
    console.error(`Error analyzing template ${templatePath}:`, error.message);
    return {
      templatePath,
      error: error.message
    };
  }
}

/**
 * Write results to file
 * @param {Object} results - Analysis results
 * @param {string} outputPath - Path to output file
 */
async function writeResults(results, outputPath) {
  try {
    if (outputPath.endsWith('.json')) {
      // JSON output
      await fs.writeFile(outputPath, JSON.stringify(results, null, 2), 'utf8');
    } else {
      // Text report output
      const report = generateSummaryReport(results);
      await fs.writeFile(outputPath, report, 'utf8');
    }
    
    console.log(`Results written to ${outputPath}`);
  } catch (error) {
    console.error('Error writing results:', error.message);
  }
}

/**
 * Parse command line arguments
 * @returns {Object} - Parsed arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const parsedArgs = {
    rulesPath: config.DEFAULT_RULES_PATH,
    templatePath: null,
    outputPath: 'analysis-results.json',
    useSageMaker: config.USE_SAGEMAKER,
    enableMultiPersona: config.ENABLE_MULTI_PERSONA,
    server: false,
    port: 3000
  };
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--rules' && i + 1 < args.length) {
      parsedArgs.rulesPath = path.resolve(args[i + 1]);
      i++;
    } else if (args[i] === '--output' && i + 1 < args.length) {
      parsedArgs.outputPath = path.resolve(args[i + 1]);
      i++;
    } else if (args[i] === '--sagemaker') {
      parsedArgs.useSageMaker = true;
    } else if (args[i] === '--docker') {
      parsedArgs.useSageMaker = false;
    } else if (args[i] === '--single-persona') {
      parsedArgs.enableMultiPersona = false;
    } else if (args[i] === '--multi-persona') {
      parsedArgs.enableMultiPersona = true;
    } else if (args[i] === '--server') {
      parsedArgs.server = true;
    } else if (args[i] === '--help' || args[i] === '-h') {
      showHelp();
      process.exit(0);
    } else if (!parsedArgs.templatePath && !args[i].startsWith('--')) {
      parsedArgs.templatePath = path.resolve(args[i]);
    }
  }
  
  // Update config with parsed args
  config.USE_SAGEMAKER = parsedArgs.useSageMaker;
  config.ENABLE_MULTI_PERSONA = parsedArgs.enableMultiPersona;
  
  return parsedArgs;
}

/**
 * Display help information
 */
function showHelp() {
  console.log(`
CloudFormation Security Analyzer

USAGE:
  node analyzer.js [OPTIONS] [template-file]

OPTIONS:
  --rules <file>         Path to rules JSON file (default: ./cloudformation-standards.json)
  --output <file>        Path to output file (default: ./analysis-results.json)
  --sagemaker            Use SageMaker endpoint for analysis
  --docker               Use Docker Model Runner for analysis (default)
  --single-persona       Use single persona analysis (faster)
  --multi-persona        Use multi-persona analysis for comprehensive results (default)
  --server               Run as MCP/A2A protocol server
  --port <number>        Port for server mode (default: 3000)
  --help, -h             Show this help message

EXAMPLES:
  # Analyze a template with default settings
  node analyzer.js template.yaml

  # Analyze with custom rules and output
  node analyzer.js --rules my-rules.json --output results.json template.yaml

  # Run as a server
  node analyzer.js --server --port 8080

  # Use SageMaker for analysis
  node analyzer.js --sagemaker template.yaml
`);
}

/**
 * Setup MCP/A2A protocol server handler
 * Follows the Agent Communication Protocol & Agent-to-Agent Protocol
 */
function setupMCPServer(port = 3000) {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  // Main endpoint for template analysis
  app.post('/analyze', async (req, res) => {
    try {
      // Validate request
      const { templateContent, rulesContent, options } = req.body;
      
      if (!templateContent) {
        return res.status(400).json({ error: 'Template content is required' });
      }
      
      // Write files to temp directory
      const tempDir = path.join(os.tmpdir(), 'cfn-analyzer-' + Date.now());
      await fs.mkdir(tempDir, { recursive: true });
      
      const templatePath = path.join(tempDir, 'template.yaml');
      await fs.writeFile(templatePath, templateContent, 'utf8');
      
      // Use provided rules or default
      let rulesPath = config.DEFAULT_RULES_PATH;
      if (rulesContent) {
        rulesPath = path.join(tempDir, 'rules.json');
        await fs.writeFile(rulesPath, JSON.stringify(rulesContent), 'utf8');
      }
      
      // Apply options from request
      if (options) {
        if (options.useSageMaker !== undefined) config.USE_SAGEMAKER = options.useSageMaker;
        if (options.multiPersona !== undefined) config.ENABLE_MULTI_PERSONA = options.multiPersona;
        if (options.temperature) config.TEMPERATURE = options.temperature;
        if (options.maxTokens) config.MAX_TOKENS = options.maxTokens;
      }
      
      // Run analysis
      const results = await analyzeTemplate(templatePath, rulesPath);
      
      // Add basic template metadata
      results.template_metadata = {
        template_size: templateContent.length,
        template_format: templateContent.trim().startsWith('{') ? 'json' : 'yaml',
        template_name: templateName
      };

      // Cleanup temp files
      try {
        await fs.rm(tempDir, { recursive: true });
      } catch (cleanupError) {
        console.warn('Error cleaning up temp files:', cleanupError);
      }
      
      // Return results
      return res.json(results);
    } catch (error) {
      console.error('Error in /analyze endpoint:', error);
      return res.status(500).json({
        error: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      });
    }
  });
  
  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', version: '1.0.0' });
  });
  
   // A2A Protocol support endpoints
  app.post('/a2a/query', async (req, res) => {
    try {
      const { query, context } = req.body;
      
      // Handle different query types
      if (query.type === 'analyze_template') {
        // For template path
        if (query.templatePath) {
          const results = await analyzeTemplate(query.templatePath, query.rulesPath || config.DEFAULT_RULES_PATH);
          return res.json({ results });
        } 
        // For template content
        else if (query.templateContent) {
          // Write template to temp file
          const tempDir = path.join(os.tmpdir(), 'cfn-analyzer-' + Date.now());
          await fs.mkdir(tempDir, { recursive: true });
          
          const templatePath = path.join(tempDir, 'template.yaml');
          await fs.writeFile(templatePath, query.templateContent, 'utf8');
          
          // Use provided rules or default
          let rulesPath = config.DEFAULT_RULES_PATH;
          if (query.rulesContent) {
            rulesPath = path.join(tempDir, 'rules.json');
            await fs.writeFile(rulesPath, JSON.stringify(query.rulesContent), 'utf8');
          }
          
          const results = await analyzeTemplate(templatePath, rulesPath);
          
          // Cleanup
          try {
            await fs.rm(tempDir, { recursive: true });
          } catch (cleanupError) {
            console.warn('Error cleaning up temp files:', cleanupError);
          }
          
          return res.json({ results });
        } else {
          return res.status(400).json({ error: 'Either templatePath or templateContent is required' });
        }
      } else if (query.type === 'validate_template') {
        try {
          let templateContent;
          
          // Get template content
          if (query.templatePath) {
            templateContent = await fs.readFile(query.templatePath, 'utf8');
          } else if (query.templateContent) {
            templateContent = query.templateContent;
          } else {
            return res.status(400).json({ error: 'Either templatePath or templateContent is required' });
          }
          
          // Validate with AWS CloudFormation
          const cfn = new CloudFormation({ region: 'us-east-1' });
          const validationResult = await cfn.validateTemplate({ TemplateBody: templateContent });
          
          // Return validation results
          return res.json({
            valid: true,
            capabilities: validationResult.Capabilities || [],
            parameters: validationResult.Parameters || [],
            description: validationResult.Description
          });
        } catch (error) {
          return res.json({
            valid: false,
            error: error.message
          });
        }
      } else if (query.type === 'parse_template') {
        try {
          let templatePath;
          
          // Get template path
          if (query.templatePath) {
            templatePath = query.templatePath;
          } else if (query.templateContent) {
            // Write template to temp file
            const tempDir = path.join(os.tmpdir(), 'cfn-analyzer-' + Date.now());
            await fs.mkdir(tempDir, { recursive: true });
            templatePath = path.join(tempDir, 'template.yaml');
            await fs.writeFile(templatePath, query.templateContent, 'utf8');
          } else {
            return res.status(400).json({ error: 'Either templatePath or templateContent is required' });
          }
          
          // Parse template
          const parsedTemplate = await loadCloudFormationTemplate(templatePath);
          
          // Cleanup if needed
          if (query.templateContent) {
            try {
              await fs.rm(path.dirname(templatePath), { recursive: true });
            } catch (cleanupError) {
              console.warn('Error cleaning up temp files:', cleanupError);
            }
          }
          
          return res.json({
            parsed: true,
            template: parsedTemplate
          });
        } catch (error) {
          return res.json({
            parsed: false,
            error: error.message
          });
        }
      } else {
        return res.status(400).json({ error: 'Unsupported query type' });
      }
    } catch (error) {
      console.error('Error in A2A query endpoint:', error);
      return res.status(500).json({ error: error.message });
    }
  });
  
  // Start the server
  return new Promise((resolve, reject) => {
    const server = app.listen(port, () => {
      console.log(`MCP/A2A server listening on port ${port}`);
      resolve(server);
    });
    
    server.on('error', (error) => {
      reject(error);
    });
  });
}

/**
 * Main function
 */
async function main() {
  try {
    const os = require('os');
    
    // Parse command line arguments
    const args = parseArgs();
    
    // Check for server mode
    if (args.server) {
      // Start MCP/A2A protocol server
      const server = await setupMCPServer(args.port || 3000);
      console.log('Server running. Press Ctrl+C to stop.');
      
      // Handle graceful shutdown
      process.on('SIGINT', () => {
        console.log('Shutting down server...');
        server.close(() => {
          console.log('Server stopped');
          process.exit(0);
        });
      });
      
      return; // Keep server running
    }
    
    if (!args.templatePath) {
      console.error('Please provide a path to a CloudFormation template');
      console.error('Usage: node analyzer.js [--rules rulesFile.json] [--output outputFile.json] [--sagemaker|--docker] [--single-persona|--multi-persona] [--server] [--port 3000] templateFile.yaml');
      process.exit(1);
    }
    
    // Run analysis
    console.log('Starting CloudFormation template analysis...');
    const results = await analyzeTemplate(args.templatePath, args.rulesPath);
    
    // Write results to file
    await writeResults(results, args.outputPath);
    
    // Display summary in console
    console.log('\nAnalysis Summary:');
    console.log(generateSummaryReport(results));
    
    console.log('Analysis complete!');
  } catch (error) {
    console.error('Error in analysis:', error.message);
    process.exit(1);
  }
}

// Run the script
main().catch(console.error);
