# Pharos Agent Carnival: Reusable Smart Contract Auditing Skills (Phase 1)

Welcome to our Phase 1 submission for the **Pharos Network Agent Carnival: Skill-to-Agent Dual Cascade Hackathon**. 

This repository contains two fully functional, production-grade, reusable **AI Agent Skills** built to run security audits on Solidity smart contracts:
1. **Solidity Static Analysis Skill**: Standardized tool that parses source code to identify structural bugs (reentrancy, visibility, unsafe auth, and unchecked returns).
2. **Solidity Threat Modeling Skill**: Standardized tool that maps access control bounds, contract roles, and architectural threat risks.

These Skills conform strictly to the **Anvita Flow** manifest specifications, enabling any autonomous agent in the Pharos ecosystem to discover, trigger, and pay for contract auditing services.

---

## Skills Architecture & Manifests

### 1. Solidity Static Analysis Skill
*   **Path**: [skills/static_analysis/](./skills/static_analysis/)
*   **Pricing**: `0.01 PHRS` per call
*   **Key Capabilities**:
    *   *Floating Pragma Check*: Flags unpinned compiler versions.
    *   *Default Visibility Check*: Scans for missing function visibility modifiers.
    *   *tx.origin Authentication*: Detects dangerous phishing access vectors.
    *   *Unchecked Low-level Call*: Identifies checks missing on `.call` and `.send` operations.
    *   *Reentrancy Check*: Lexes function lines to check if state assignments happen after an external call.

#### Manifest (`manifest.json`)
```json
{
  "name": "solidity_static_analysis",
  "display_name": "Solidity Static Analysis",
  "description": "Scans Solidity source code for structural security vulnerabilities...",
  "version": "1.0.0",
  "category": "Security",
  "pricing": {
    "token": "PHRS",
    "price_per_call": "0.01"
  },
  "inputs": {
    "source_code": {
      "type": "string",
      "description": "The raw Solidity smart contract source code to audit.",
      "required": true
    }
  },
  "outputs": {
    "vulnerabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "name": { "type": "string" },
          "severity": { "type": "string" },
          "line": { "type": "integer" },
          "snippet": { "type": "string" },
          "description": { "type": "string" },
          "remediation": { "type": "string" }
        }
      }
    },
    "score": { "type": "integer" }
  }
}
```

---

### 2. Solidity Threat Modeling Skill
*   **Path**: [skills/threat_modeling/](./skills/threat_modeling/)
*   **Pricing**: `0.015 PHRS` per call
*   **Key Capabilities**:
    *   *User Roles Extraction*: Discovers defined administrative state variables and custom privilege classes (Owner, Admin, custom roles).
    *   *Privileged Functions Registry*: Maps all restricted access-control modifiers (`onlyOwner`, custom modifier constraints, require-auth).
    *   *Unprotected sensitive updates*: Flags public functions altering variables like fees, rates, and limits without access modifiers.
    *   *Arithmetic Overflow Risk*: Warns on SafeMath omissions for pre-0.8.0 solidity compilers.
    *   *Oracle Manipulation Risk*: Identifies spot price dependency vulnerability patterns within contract calculation flows.

#### Manifest (`manifest.json`)
```json
{
  "name": "solidity_threat_modeling",
  "display_name": "Solidity Threat Modeling",
  "description": "Analyzes smart contract functions, privilege levels, and modifiers to model access control boundaries...",
  "version": "1.0.0",
  "category": "Security",
  "pricing": {
    "token": "PHRS",
    "price_per_call": "0.015"
  },
  "inputs": {
    "source_code": {
      "type": "string",
      "description": "The Solidity contract code to analyze.",
      "required": true
    }
  },
  "outputs": {
    "roles": { "type": "array", "items": { "type": "string" } },
    "privileged_functions": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "modifier": { "type": "string" },
          "line": { "type": "integer" }
        }
      }
    },
    "threats": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "title": { "type": "string" },
          "severity": { "type": "string" },
          "description": { "type": "string" },
          "remediation": { "type": "string" }
        }
      }
    }
  }
}
```

---

## Getting Started & Testing

Verify both skills against our unit test suites and CLI audit harness.

### 1. Clone the Repository
```bash
git clone https://github.com/0xnald/pharos-audit-skillpack.git
cd pharos-audit-skillpack
```

### 2. Prerequisites
- Python 3.8+ (No external third-party dependencies are required. The parsers run natively using Python's standard `re` and compiler tools).

### 2. Run Unit Tests
To run unit tests for the Static Analysis Skill:
```bash
python skills/static_analysis/test_skill.py
```

To run unit tests for the Threat Modeling Skill:
```bash
python skills/threat_modeling/test_skill.py
```

### 3. Run Audit Test Harness
To run the CLI test harness, which scans two sample smart contracts (`VulnerableBank.sol` and `SecureBank.sol`) and prints formatted reports:
```bash
python test_harness.py
---

## Programmatic Integration & API Usage

For other builders and agents in the Pharos Network / Anvita Flow ecosystem, here is how you can invoke and integrate these skills:

### 1. Python Integration
If you are developing a Python-based agent, you can import and call the handlers directly:

```python
from skills.static_analysis import handler as static_analyzer
from skills.threat_modeling import handler as threat_modeler

source_code = """
pragma solidity 0.8.20;
contract Simple {
    address public owner;
}
"""

# Run static analysis
static_report = static_analyzer.analyze(source_code)
print("Static Score:", static_report["score"])

# Run threat modeling
threat_report = threat_modeler.analyze(source_code)
print("Found Roles:", threat_report["roles"])
```

### 2. HTTP API Integration (A2A Gateway)
When deployed inside an Anvita Flow container, the skills are invoked via a standard HTTP POST request.

**Request:**
*   **Method**: `POST`
*   **Headers**: `Content-Type: application/json`
*   **Body**:
    ```json
    {
      "source_code": "pragma solidity ^0.8.0; contract Test {}"
    }
    ```

**Example JSON Response (Static Analysis)**:
```json
{
  "vulnerabilities": [
    {
      "id": "SOL-PRAGMA-001",
      "name": "Floating Pragma",
      "severity": "Low",
      "line": 2,
      "snippet": "pragma solidity ^0.8.0;",
      "description": "The contract uses a floating pragma (^0.8.0)...",
      "remediation": "Lock the compiler version..."
    }
  ],
  "score": 97
}
```

---

## Phase 2 Progression (Preview)

Upon selecting these Skills for the Skill Hub registry, they can be deployed using **Anvita Flow Infra**. In **Phase 2 (Agent Arena)**, we will build a **Lead Auditor Orchestrator Agent** that:
1. Dynamically accepts audit requests.
2. Settles A2A payments on the **Pharos Testnet** (RPC: `https://testnet.dplabs-internal.com`, Chain ID: `688688`) to the sub-agent skills using the native token `PHRS`.
3. Consolidates the outputs into a single report, served through a premium dark-themed web interface.
