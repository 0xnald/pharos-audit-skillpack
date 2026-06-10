import os
import sys
import json

# Add skills to search path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'skills'))

from static_analysis import handler as static_handler
from threat_modeling import handler as threat_handler

def run_test_harness():
    samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tests', 'samples')
    
    contracts = [
        {"name": "VulnerableBank.sol", "path": os.path.join(samples_dir, "VulnerableBank.sol")},
        {"name": "SecureBank.sol", "path": os.path.join(samples_dir, "SecureBank.sol")}
    ]
    
    print("=========================================================")
    print("    Pharos Agent Carnival: Smart Contract Audit Harness  ")
    print("=========================================================")
    
    for contract in contracts:
        name = contract["name"]
        path = contract["path"]
        
        print(f"\nAnalyzing contract: {name} ...")
        
        if not os.path.exists(path):
            print(f"Error: file not found at {path}")
            continue
            
        with open(path, 'r', encoding='utf-8') as f:
            code = f.read()
            
        # Run Static Analysis Skill
        static_result = static_handler.analyze(code)
        
        # Run Threat Modeling Skill
        threat_result = threat_handler.analyze(code)
        
        print(f"--- Static Analysis Result ({name}) ---")
        print(f"Health Score: {static_result['score']}/100")
        print(f"Vulnerabilities Found: {len(static_result['vulnerabilities'])}")
        for v in static_result['vulnerabilities']:
            print(f"  [{v['severity']}] {v['name']} (Line {v['line']}): {v['description']}")
            print(f"    Code snippet: {v['snippet']}")
            print(f"    Remediation: {v['remediation']}")
            print("")
            
        print(f"--- Threat Modeling Result ({name}) ---")
        print(f"Mapped Roles: {', '.join(threat_result['roles'])}")
        print(f"Privileged Functions: {len(threat_result['privileged_functions'])}")
        for pf in threat_result['privileged_functions']:
            print(f"  - {pf['name']} (Line {pf['line']}): restricted by {pf['modifier']}")
            
        print(f"Mapped Security Threats: {len(threat_result['threats'])}")
        for t in threat_result['threats']:
            print(f"  [{t['severity']}] {t['title']}")
            print(f"    Description: {t['description']}")
            print(f"    Remediation: {t['remediation']}")
            print("")
            
        print("-" * 57)

if __name__ == "__main__":
    run_test_harness()
