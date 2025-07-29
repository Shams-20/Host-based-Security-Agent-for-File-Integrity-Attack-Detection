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
