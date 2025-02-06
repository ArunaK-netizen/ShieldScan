import yara

def yara_scan(file_path, rule_path='rule.yara'):
    """Scan a file using YARA rules."""
    try:
        rules = yara.compile(filepath=rule_path)
        matches = rules.match(file_path)

        if matches:
            print(f"YARA matches found: {matches}")
            return "unsafe"
        return "safe"
    except Exception as e:
        return f"Error in YARA scan: {str(e)}"
