import re

def strip_comments_keep_lines(code):
    """Strips comments preserving line numbers and character index offsets."""
    def repl_single(match):
        return ' ' * len(match.group(0))
    code = re.sub(r'//.*', repl_single, code)

    def repl_multi(match):
        return re.sub(r'[^\n]', ' ', match.group(0))
    code = re.sub(r'/\*.*?\*/', repl_multi, code, flags=re.DOTALL)
    return code

def analyze(source_code):
    """
    Analyzes Solidity contract code to generate an architectural threat model.
    """
    clean_code = strip_comments_keep_lines(source_code)
    lines = source_code.split('\n')
    clean_lines = clean_code.split('\n')
    
    roles = set(["User"])  # Everyone has user role by default
    privileged_functions = []
    threats = []
    
    # --- 1. Identify Roles ---
    # Check for owner/admin state variables
    owner_var_pattern = re.compile(r'\baddress\s+(?:public\s+|private\s+|internal\s+)?(\w*owner\w*)\b', re.IGNORECASE)
    admin_var_pattern = re.compile(r'\baddress\s+(?:public\s+|private\s+|internal\s+)?(\w*admin\w*)\b', re.IGNORECASE)
    role_constant_pattern = re.compile(r'\bbytes32\s+public\s+constant\s+(\w+_ROLE)\b')
    role_mapping_pattern = re.compile(r'\bmapping\s*\(\s*address\s*=>\s*bool\s*\)\s+(?:public\s+|private\s+|internal\s+)?is(\w+)\b', re.IGNORECASE)
    
    for line in clean_lines:
        # Check variable declarations
        match_owner = owner_var_pattern.search(line)
        if match_owner:
            roles.add("Owner")
            
        match_admin = admin_var_pattern.search(line)
        if match_admin:
            roles.add("Admin")
            
        # Check OpenZeppelin AccessControl role constants
        match_role = role_constant_pattern.search(line)
        if match_role:
            role_name = match_role.group(1).replace('_ROLE', '').title()
            roles.add(role_name)
            
        # Check custom role mappings: isManager, isWhitelisted, etc.
        match_mapping = role_mapping_pattern.search(line)
        if match_mapping:
            roles.add(match_mapping.group(1).title())
            
    # --- 2. Identify Privileged Functions & Check Modifiers ---
    # Match function headers to find custom modifiers or require checks
    func_pattern = re.compile(r'\bfunction\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*([^{;]*)\{', re.DOTALL)
    
    # Common auth modifiers
    auth_modifiers = ['onlyOwner', 'onlyAdmin', 'onlyRole', 'restricted', 'onlyAuthorized', 'checkRole']
    
    for match in func_pattern.finditer(clean_code):
        func_name = match.group(1)
        modifiers_str = match.group(3).strip()
        
        char_index = match.start()
        line_num = clean_code[:char_index].count('\n') + 1
        
        # Determine if it has a modifier
        matched_modifier = None
        for mod in auth_modifiers:
            if mod in modifiers_str:
                matched_modifier = mod
                break
                
        # Also check inside the function body for manual require auth checks
        # e.g., require(msg.sender == owner);
        open_bracket_index = match.end() - 1
        def find_matching_bracket(text, start_index):
            count = 0
            for idx in range(start_index, len(text)):
                if text[idx] == '{':
                    count += 1
                elif text[idx] == '}':
                    count -= 1
                    if count == 0:
                        return idx
            return -1
            
        close_bracket_index = find_matching_bracket(clean_code, open_bracket_index)
        has_manual_require_auth = False
        if close_bracket_index != -1:
            func_body = clean_code[open_bracket_index:close_bracket_index+1]
            # Match patterns like: require(msg.sender == owner) or require(owner == msg.sender)
            require_auth_pattern = re.compile(r'\brequire\s*\(\s*(msg\.sender\s*==\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*==\s*msg\.sender)\b')
            if require_auth_pattern.search(func_body):
                has_manual_require_auth = True
                matched_modifier = "manual require"
                
        if matched_modifier:
            privileged_functions.append({
                "name": func_name,
                "modifier": matched_modifier,
                "line": line_num
            })

    # --- 3. Threat Modeling Heuristics ---

    # Threat A: Unprotected State Mutators (Centralization or Exploit Risk)
    # If a function is public/external, is NOT privileged, and updates sensitive variables:
    sensitive_var_pattern = re.compile(r'\b(owner|admin|price|rate|fee|limit|paused|balance|whitelist)\b', re.IGNORECASE)
    state_write_regex = re.compile(r'\b[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)?(?:\s*\[[^\]]*\])*\s*(?:[-+*/%&|^]|\*\*|)=(?!=)|\b[a-zA-Z0-9_]+\s*\+\+|\b[a-zA-Z0-9_]+\s*--')

    for match in func_pattern.finditer(clean_code):
        func_name = match.group(1)
        modifiers_str = match.group(3).strip()
        char_index = match.start()
        line_num = clean_code[:char_index].count('\n') + 1
        
        # Skip constructors, getters, view/pure functions, and private/internal functions
        is_write_func = 'view' not in modifiers_str and 'pure' not in modifiers_str
        is_accessible = 'public' in modifiers_str or 'external' in modifiers_str or not any(v in modifiers_str for v in ['internal', 'private'])
        
        if is_write_func and is_accessible and func_name != "constructor":
            # Check if it lacks any access control
            is_privileged = any(pf["name"] == func_name for pf in privileged_functions)
            if not is_privileged:
                # Get function body to see if it modifies sensitive variables
                open_bracket_index = match.end() - 1
                close_bracket_index = find_matching_bracket(clean_code, open_bracket_index)
                if close_bracket_index != -1:
                    func_body = clean_code[open_bracket_index:close_bracket_index+1]
                    # Check if body contains write statements that modify sensitive state variables
                    body_lines = func_body.split('\n')
                    for local_line_num, b_line in enumerate(body_lines):
                        if state_write_regex.search(b_line) and sensitive_var_pattern.search(b_line):
                            is_local_decl = any(b_line.strip().startswith(kw) for kw in ['uint', 'int', 'address', 'bool', 'bytes', 'string', 'let', 'var'])
                            if not is_local_decl:
                                threats.append({
                                    "id": "THREAT-CTRL-001",
                                    "title": "Unprotected Sensitive State Update",
                                    "severity": "High",
                                    "description": f"Function '{func_name}' is public/external and has no access control modifier, but modifies sensitive variable on line {line_num + local_line_num} ('{b_line.strip()}'). Any user can invoke this function and change critical parameters.",
                                    "remediation": "Add an access control modifier (e.g. onlyOwner) or restrict function visibility to internal/private."
                                })
                                break

    # Threat B: Arithmetic Overflow/Underflow in Pre-0.8.0 Solidity without SafeMath
    pragma_pattern = re.compile(r'\bpragma\s+solidity\s+([^;]+);')
    is_pre_08 = False
    uses_safemath = False
    
    for line in clean_lines:
        match_pragma = pragma_pattern.search(line)
        if match_pragma:
            version_expr = match_pragma.group(1).strip()
            # Checks if version is explicitly pre-0.8 (e.g. 0.7.0, 0.6.12, 0.5.0, etc.)
            # If the expression contains 0.7 or 0.6 or 0.5 or 0.4
            if any(v in version_expr for v in ['0.4.', '0.5.', '0.6.', '0.7.']):
                is_pre_08 = True
        if 'SafeMath' in line:
            uses_safemath = True
            
    if is_pre_08 and not uses_safemath:
        threats.append({
            "id": "THREAT-MATH-001",
            "title": "Arithmetic Overflow Risk (Pre-0.8.0 missing SafeMath)",
            "severity": "High",
            "description": "The contract targets a Solidity compiler version below 0.8.0, where arithmetic operations are subject to silent wrapping overflow and underflow, but does not import or use OpenZeppelin SafeMath.",
            "remediation": "Upgrade the compiler version to at least 0.8.0 (where checks are built-in), or import SafeMath and use 'using SafeMath for uint256;'."
        })

    # Threat C: Spot Price Oracle Dependency (Flash Loan Vulnerability)
    oracle_regex = re.compile(r'\b(uniswapV2Pair|getReserves|balanceOf|slot0)\b')
    for match in func_pattern.finditer(clean_code):
        func_name = match.group(1)
        open_bracket_index = match.end() - 1
        close_bracket_index = find_matching_bracket(clean_code, open_bracket_index)
        if close_bracket_index != -1:
            func_body = clean_code[open_bracket_index:close_bracket_index+1]
            if oracle_regex.search(func_body) and any(op in func_body for op in ['/', '*']):
                char_index = match.start()
                line_num = clean_code[:char_index].count('\n') + 1
                threats.append({
                    "id": "THREAT-ORACLE-001",
                    "title": "Manipulation Risk of Spot Price Oracle",
                    "severity": "Medium",
                    "description": f"Function '{func_name}' (starting on line {line_num}) queries pool balances or reserves and performs mathematical calculations. This is vulnerable to flash loan manipulation of spot market reserves.",
                    "remediation": "Use a Time-Weighted Average Price (TWAP) oracle (e.g. Uniswap V3 Oracle) or a decentralized oracle network feed (e.g. Chainlink Data Feeds)."
                })
                break

    # Threat D: Centralization Risk (Too much authority in Owner/Admin role)
    # If the number of privileged functions is greater than 3, raise awareness
    if len(privileged_functions) > 3:
        threats.append({
            "id": "THREAT-CENT-001",
            "title": "Centralization Risk (Excessive Privileged Control)",
            "severity": "Low",
            "description": f"The contract defines {len(privileged_functions)} privileged functions controlled by restricted roles. If the owner's private key is compromised, the entire system can be easily frozen, drained, or bricked.",
            "remediation": "Use a multi-signature wallet (e.g., Gnosis Safe) for the admin owner, implement a timelock contract, or move governance control to a DAO."
        })

    return {
        "roles": list(roles),
        "privileged_functions": privileged_functions,
        "threats": threats
    }
