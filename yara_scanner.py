import yara
import os

def compile_rules(rules_dir):
    rules = {}
    for filename in os.listdir(rules_dir):
        if filename.endswith(".yara") or filename.endswith(".yar"):
            path = os.path.join(rules_dir, filename)
            rules[filename] = path
    return yara.compile(filepaths=rules) if rules else None

def scan_file_with_yara(file_path, yara_rules):
    try:
        matches = yara_rules.match(file_path)
        return matches
    except Exception as e:
        print(f"🛑 YARA scan error for {file_path}: {e}")
        return []

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 yara_scanner.py <file_to_scan>")
        exit(1)

    file_to_scan = sys.argv[1]
    rules = compile_rules("yara_rules")

    if rules:
        matches = scan_file_with_yara(file_to_scan, rules)
        if matches:
            print(f"⚠️ YARA Match Found in {file_to_scan}!")
            for match in matches:
                print(f"Matched Rule: {match.rule}")
        else:
            print(f"✅ No YARA match in {file_to_scan}")
    else:
        print("❌ No YARA rules loaded.")
