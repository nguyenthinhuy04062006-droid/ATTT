"""Script to verify that no forbidden cryptographic libraries or modules are imported.
Complies with Academic Integrity rules for the Information Security project.
"""

import ast
import os
import sys

FORBIDDEN_MODULES = {
    "cryptography",
    "crypto",
    "cryptodome",
    "nacl",
    "openssl",
    "pyopenssl",
    "m2crypto",
    "gmpy2",
    "ecdsa",
    "rsa",
    "pycrypto",
    "passlib",
    "bcrypt",
    "paramiko",
    "hashlib",
    "hmac",
    "ssl",
}

FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "__import__",
}


class ImportChecker(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.violations = []

    def visit_Import(self, node):
        for alias in node.names:
            base_module = alias.name.split(".")[0].lower()
            if base_module in FORBIDDEN_MODULES:
                self.violations.append(
                    f"{self.filename}:{node.lineno} - Forbidden import: '{alias.name}'"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split(".")[0].lower()
            if base_module in FORBIDDEN_MODULES:
                self.violations.append(
                    f"{self.filename}:{node.lineno} - Forbidden from-import: '{node.module}'"
                )
            if base_module == "importlib":
                self.violations.append(
                    f"{self.filename}:{node.lineno} - Forbidden use of dynamic import library: '{node.module}'"
                )
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_CALLS:
                self.violations.append(
                    f"{self.filename}:{node.lineno} - Forbidden dynamic execution call: '{node.func.id}()'"
                )
        self.generic_visit(node)


def scan_directory(base_dir):
    all_violations = []
    scanned_files = 0
    dirs_to_scan = ["src", "tests", "tools"]

    for d in dirs_to_scan:
        path = os.path.join(base_dir, d)
        if not os.path.exists(path):
            continue
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    scanned_files += 1
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            tree = ast.parse(f.read(), filename=file_path)
                        checker = ImportChecker(file_path)
                        checker.visit(tree)
                        all_violations.extend(checker.violations)
                    except Exception as e:
                        all_violations.append(f"{file_path}: Error parsing file: {e}")

    # Also check root level python scripts like benchmark.py if present
    for file in os.listdir(base_dir):
        if file.endswith(".py"):
            file_path = os.path.join(base_dir, file)
            scanned_files += 1
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=file_path)
                checker = ImportChecker(file_path)
                checker.visit(tree)
                all_violations.extend(checker.violations)
            except Exception as e:
                all_violations.append(f"{file_path}: Error parsing file: {e}")

    return scanned_files, all_violations


def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print(f"Scanning project directory for forbidden imports: {base_dir}")
    scanned_files, violations = scan_directory(base_dir)

    print(f"Total Python files scanned: {scanned_files}")
    if violations:
        print("\n[CRITICAL FAILURE] Forbidden modules or calls detected:")
        for v in violations:
            print(f"  - {v}")
        sys.exit(1)
    else:
        print("\n[PASS] No forbidden crypto libraries or dynamic imports detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()
