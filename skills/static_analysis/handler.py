import re

def strip_comments_keep_lines(code):
    """
    Strips single-line and multi-line comments from Solidity code,
    replacing characters with spaces to preserve line numbers and offsets.
    """
    # Replace single-line comments // ... with spaces of the same length
    def repl_single(match):
        return ' ' * len(match.group(0))
    code = re.sub(r'//.*', repl_single, code)

    # Replace multi-line comments /* ... */ preserving newlines
    def repl_multi(match):
        return re.sub(r'[^\n]', ' ', match.group(0))
    code = re.sub(r'/\*.*?\*/', repl_multi, code, flags=re.DOTALL)
    return code

def analyze(source_code):
    """
    Analyzes Solidity source code for structural security vulnerabilities.
    Returns a dictionary matching the manifest output schema.
    """
    vulnerabilities = []
    
    # Clean the code while preserving line numbers
    clean_code = strip_comments_keep_lines(source_code)
    lines = source_code.split('\n')
    clean_lines = clean_code.split('\n')

    # --- 1. Floating Pragma Check ---
    # Look for pragma solidity statement
    pragma_pattern = re.compile(r'\bpragma\s+solidity\s+([^;]+);')
    for i, line in enumerate(clean_lines):
        match = pragma_pattern.search(line)
        if match:
            version_expr = match.group(1).strip()
            # If it uses ^, >, < or contains wildcards, it's floating/unsafe
            if any(char in version_expr for char in ['^', '>', '<', '*']):
                vulnerabilities.append({
                    "id": "SOL-PRAGMA-001",
                    "name": "Floating Pragma",
                    "severity": "Low",
                    "line": i + 1,
                    "snippet": lines[i].strip(),
                    "description": f"The contract uses a floating pragma ({version_expr}). This allows compiling with multiple compiler versions which may introduce undiscovered bugs or compiler vulnerabilities.",
                    "remediation": "Lock the compiler version to a single specific release (e.g. pragma solidity 0.8.20;)."
                })

    # --- 2. Default Function Visibility Check ---
    # Parse function declarations and check for visibility modifiers
    # This matches: function <name>(<args>) <modifiers> {
    # We find where function starts and match until the opening bracket {
    # Note: fallback functions or constructors should also be checked.
    func_pattern = re.compile(r'\bfunction\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*([^{;]*)', re.DOTALL)
    for match in func_pattern.finditer(clean_code):
        func_name = match.group(1)
        modifiers = match.group(3)
        
        # Determine the line number of this function declaration
        char_index = match.start()
        line_num = clean_code[:char_index].count('\n') + 1
        
        # Skip if it is an interface or abstract contract function without body (ends with semicolon)
        # We can inspect the code following the match to check if it's a declaration or definition
        following_code = clean_code[match.end():].strip()
        if following_code.startswith(';'):
            continue
            
        # Check if visibility is specified
        has_visibility = any(v in modifiers for v in ['public', 'external', 'internal', 'private'])
        if not has_visibility and func_name != "constructor":
            vulnerabilities.append({
                "id": "SOL-VIS-001",
                "name": "Default Function Visibility",
                "severity": "Medium",
                "line": line_num,
                "snippet": lines[line_num - 1].strip(),
                "description": f"Function '{func_name}' does not specify an explicit visibility modifier. It will default to 'public', potentially exposing it to unauthorized callers.",
                "remediation": "Explicitly declare visibility (public, external, internal, or private) for all functions."
            })

    # --- 3. tx.origin Authentication Check ---
    tx_origin_pattern = re.compile(r'\btx\.origin\b')
    for i, line in enumerate(clean_lines):
        if tx_origin_pattern.search(line):
            vulnerabilities.append({
                "id": "SOL-AUTH-001",
                "name": "Use of tx.origin",
                "severity": "High",
                "line": i + 1,
                "snippet": lines[i].strip(),
                "description": "The contract uses 'tx.origin' for authorization checks. This makes it vulnerable to phishing/social engineering attacks where a malicious contract acts as a proxy.",
                "remediation": "Use 'msg.sender' instead of 'tx.origin' for ownership/access control checks."
            })

    # --- 4. Unchecked Call Return Check ---
    # Find low-level calls (.call, .delegatecall, .send) that aren't wrapped in checked statements
    for i, line in enumerate(clean_lines):
        call_match = re.search(r'\.(call|send|delegatecall)\b', line)
        if call_match and ';' in line:
            # Check if it has an assignment or is inside require/if/assert
            no_comparisons = re.sub(r'(==|<=|>=|!=)', '  ', line)
            has_assignment = '=' in no_comparisons
            has_check = any(kw in line for kw in ['require', 'assert', 'if'])
            
            if not (has_assignment or has_check):
                call_type = call_match.group(1)
                vulnerabilities.append({
                    "id": "SOL-CALL-001",
                    "name": f"Unchecked low-level {call_type}",
                    "severity": "Medium",
                    "line": i + 1,
                    "snippet": lines[i].strip(),
                    "description": f"The return value of a low-level '{call_type}' is not checked. If the call fails, execution will continue silently, potentially causing inconsistent state.",
                    "remediation": "Always capture the boolean return value (e.g., (bool success, ) = target.call(...);) and verify it using require(success);."
                })

    # --- 5. Reentrancy Check ---
    # Identify functions that execute external calls (call, transfer, send) BEFORE modifying state variables.
    # We parse function blocks to check order of operations.
    # First, let's find the range of each function definition (from '{' to matching '}')
    def find_matching_bracket(text, start_index):
        bracket_count = 0
        for idx in range(start_index, len(text)):
            if text[idx] == '{':
                bracket_count += 1
            elif text[idx] == '}':
                bracket_count -= 1
                if bracket_count == 0:
                    return idx
        return -1

    func_def_pattern = re.compile(r'\bfunction\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)[^{]*\{')
    for match in func_def_pattern.finditer(clean_code):
        func_name = match.group(1)
        open_bracket_index = match.end() - 1
        close_bracket_index = find_matching_bracket(clean_code, open_bracket_index)
        
        if close_bracket_index != -1:
            func_body = clean_code[open_bracket_index:close_bracket_index + 1]
            func_line_offset = clean_code[:open_bracket_index].count('\n')
            
            # Find any lines in the body that do external calls
            # Matches: call{value: ...}(), send(), transfer()
            call_regex = re.compile(r'\b(call|send|transfer)\b')
            state_write_regex = re.compile(r'\b[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)?(?:\s*\[[^\]]*\])*\s*(?:[-+*/%&|^]|\*\*|)=(?!=)|\b[a-zA-Z0-9_]+\s*\+\+|\b[a-zA-Z0-9_]+\s*--')

            calls = []
            writes = []
            
            body_lines = func_body.split('\n')
            for local_line_num, body_line in enumerate(body_lines):
                # Search for calls
                if call_regex.search(body_line):
                    calls.append(local_line_num)
                # Search for state variable assignments or updates
                # Note: we filter out updates to local variables (like loop index i++, or memory arrays)
                # For simplicity, if it contains an assignment operator and does not start with a type declaration (uint, address, bool, bytes) or 'let'
                if state_write_regex.search(body_line):
                    is_local_decl = any(body_line.strip().startswith(kw) for kw in ['uint', 'int', 'address', 'bool', 'bytes', 'string', 'mapping', 'struct', 'let', 'var'])
                    if not is_local_decl:
                        writes.append(local_line_num)
            
            # If a call occurs before a state write, flag it
            reentrancy_occurred = False
            first_call_line = -1
            first_write_after_call = -1
            
            for call_line in calls:
                post_call_writes = [w for w in writes if w > call_line]
                if post_call_writes:
                    reentrancy_occurred = True
                    first_call_line = call_line
                    first_write_after_call = post_call_writes[0]
                    break
            
            if reentrancy_occurred:
                global_call_line = func_line_offset + first_call_line + 1
                global_write_line = func_line_offset + first_write_after_call + 1
                vulnerabilities.append({
                    "id": "SOL-REENTRANCY-001",
                    "name": "Potential Reentrancy Vulnerability",
                    "severity": "High",
                    "line": global_call_line,
                    "snippet": lines[global_call_line - 1].strip(),
                    "description": f"Potential reentrancy vulnerability in function '{func_name}'. An external call is made on line {global_call_line}, followed by a state modification on line {global_write_line} ('{lines[global_write_line - 1].strip()}').",
                    "remediation": "Apply the Checks-Effects-Interactions pattern: update all state variables before making external calls, or use a reentrancy guard modifier."
                })

    # --- 6. Security Health Score Calculation ---
    # Base score is 100. Subtract based on severity of vulnerabilities found.
    # Max deductions capped to ensure score stays within [0, 100].
    score = 100
    for vuln in vulnerabilities:
        if vuln["severity"] == "High":
            score -= 25
        elif vuln["severity"] == "Medium":
            score -= 10
        elif vuln["severity"] == "Low":
            score -= 3
            
    score = max(0, min(100, score))

    return {
        "vulnerabilities": vulnerabilities,
        "score": score
    }
