#!/usr/bin/env python3
import subprocess
import tempfile

# Test with a simple vulnerable snippet
test_code = """
using System;
using System.Data.SqlClient;

public class Test {
    public void Vulnerable(string userInput) {
        string query = "SELECT * FROM users WHERE id = " + userInput;
        // SQL Injection vulnerability
    }
}
"""

with tempfile.NamedTemporaryFile("w", suffix=".cs", delete=False) as f:
    f.write(test_code)
    tmp_path = f.name

cmd = ["semgrep", "scan", "--config", "p/security-audit", "--config", "p/csharp", "--json", tmp_path]
print(f"Running: {' '.join(cmd)}")

result = subprocess.run(cmd, capture_output=True, text=True)
print(f"\nReturn code: {result.returncode}")
print(f"Findings: {result.stdout}")
print(f"Errors: {result.stderr}")