import os
import re



# File types to scan (filtering out binaries)
ALLOWED_EXTENSIONS = (".txt", ".py", ".csv", ".log", ".json", ".xml")

# Improved patterns
PATTERNS = {
    "Email": r"[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+",
    "Phone Number": r"(\+\d{1,3}[- ]?)?\d{10}",
    "Credit Card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Password (weak detection)": r"(?i)password\s*[:=]\s*\S+"
}



def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()

            for data_type, pattern in PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    findings.append((data_type, match))

    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}")

    return findings


def scan_directory(directory):
    results = {}

    for root, dirs, files in os.walk(directory):
        for file in files:
            if not file.endswith(ALLOWED_EXTENSIONS):
                continue  # Skip unwanted file types

            file_path = os.path.join(root, file)
            findings = scan_file(file_path)

            if findings:
                results[file_path] = findings

    return results


# ---------------- UI (CLI BASED) ---------------- #

def print_banner():
    print("=" * 60)
    print("🔐 PERSONAL DATA LEAK MONITOR (CLI VERSION)")
    print("=" * 60)


def print_results(results):
    if not results:
        print("\n✅ No sensitive data found.")
        return

    print("\n🚨 Sensitive Data Detected:\n")

    for file, findings in results.items():
        print(f"📁 File: {file}")

        for data_type, match in findings:
            print(f"   ➤ {data_type}: {match}")

        print("-" * 50)


# ---------------- MAIN ---------------- #

import sys

if __name__ == "__main__":
    print_banner()

    # Accept folder path as command-line argument (fixes VS Code Run issue)
    if len(sys.argv) > 1:
        folder_path = sys.argv[1]
    else:
        print("❌ No folder path provided.")
        print("👉 Usage: python scanner.py <folder_path>")
        exit()

    if not folder_path:
        print("❌ No path entered.")
    elif not os.path.exists(folder_path):
        print("❌ Invalid folder path.")
    else:
        print("\n🔍 Scanning... Please wait...\n")
        try:
            results = scan_directory(folder_path)
            print_results(results)
        except Exception as e:
            print(f"❌ Scanning failed: {e}")