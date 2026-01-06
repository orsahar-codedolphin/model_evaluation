#!/usr/bin/env python3
import os, json, subprocess, tempfile, glob, html, sys
from datetime import datetime
import shutil
from collections import defaultdict
import webbrowser
from flask import Flask, send_from_directory, render_template_string
import threading
import argparse

CUSTOM_CONFIG_PATH = "config/semgrep_custom_config.json"

def load_vuln_config(config_path="validate.json"):
    with open(config_path, "r") as f:
        return json.load(f)


def load_custom_semgrep_config(config_path="semgrep_custom_config.json"):
    """Load custom semgrep configuration with additional --config paths"""
    if not os.path.exists(config_path):
        print(f"⚠ Custom config not found: {config_path}, using default rules only")
        return {}
    
    with open(config_path, "r") as f:
        custom_config = json.load(f)
    
    print(f"✓ Loaded custom semgrep config: {len(custom_config.get('--config', []))} custom rules")
    return custom_config


def build_semgrep_command(tmp_path, custom_config=None):
    """Build semgrep command with default and custom configs"""
    cmd = ["semgrep", "scan"]
    
    # Add default configs
    cmd.extend(["--config", "p/security-audit"])
    cmd.extend(["--config", "p/csharp"])
    
    # Add custom configs if provided
    if custom_config and "--config" in custom_config:
        config_paths = custom_config["--config"]
        
        # Handle both single string and list of strings
        if isinstance(config_paths, str):
            config_paths = [config_paths]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                cmd.extend(["--config", config_path])
                print(f"    + Using custom rule: {config_path}")
            else:
                print(f"    ⚠ Custom rule not found: {config_path}")
    
    cmd.extend(["--json", tmp_path])
    return cmd


def scan_jsonl_file(jsonl_path, output_dir, run_label, vuln_type, custom_config=None, max_snippets=None):
    """Scan a JSONL file with semgrep and return results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create a timestamped local copy with vuln type in name
    base_name = f"{vuln_type}_{os.path.basename(jsonl_path).replace('.jsonl', '')}_{run_label}_{timestamp}.jsonl"
    local_copy = os.path.join(output_dir, base_name)
    shutil.copy2(jsonl_path, local_copy)
    print(f"Local copy created: {local_copy}")

    all_results = []
    total_snippets = total_lines = total_findings = 0
    severity_counts = defaultdict(int)
    rule_counts = defaultdict(int)

    print(f"Scanning file: {jsonl_path}")
    if custom_config:
        print(f"  Using custom semgrep rules")
    
    snippet_count = 0
    
    with open(jsonl_path) as f:
        for line in f:
            if max_snippets and snippet_count >= max_snippets:
                break
            try:
                obj = json.loads(line)
                code = obj.get("response")
                if not code:
                    continue
                
                # Strip markdown code fences if present
                code = code.strip()
                if code.startswith("```"):
                    lines = code.split("\n")
                    lines = lines[1:]
                    if lines and lines[-1].strip() == "```":
                        lines = lines[:-1]
                    code = "\n".join(lines)
                
            except json.JSONDecodeError:
                continue
            
            snippet_count += 1
            total_snippets += 1
            total_lines += len(code.splitlines())

            with tempfile.NamedTemporaryFile("w", suffix=".cs", delete=False) as tmp:
                tmp.write(code)
                tmp_path = tmp.name
            
            try:
                print(f"  Snippet {snippet_count}: scanning... (code lines: {len(code.splitlines())})", end="", flush=True)
                
                # Build command with custom configs
                cmd = build_semgrep_command(tmp_path, custom_config)
                
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=60
                )
                
                os.unlink(tmp_path)

                if result.returncode not in [0, 1]:
                    print(f" → semgrep error (code {result.returncode})")
                    if result.stderr:
                        print(f"    stderr: {result.stderr[:300]}")
                    continue
                
                if not result.stdout.strip():
                    print(f" → empty output")
                    continue

                parsed = json.loads(result.stdout)
                parsed["source_file"] = jsonl_path
                parsed["snippet_index"] = snippet_count
                parsed["prompt"] = obj.get("prompt", "")
                parsed["code"] = code
                
                findings = parsed.get("results", [])
                total_findings += len(findings)
                
                for finding in findings:
                    severity = finding.get("extra", {}).get("severity", "unknown")
                    severity_counts[severity] += 1
                    rule_id = finding.get("check_id", "unknown")
                    rule_counts[rule_id] += 1
                
                all_results.append(parsed)
                print(f" → {len(findings)} findings")
                
            except subprocess.TimeoutExpired:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                print(f" → TIMEOUT after 60s")
            except Exception as e:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                print(f" → error: {e}")

    return {
        "results": all_results,
        "stats": {
            "label": run_label,
            "vuln_type": vuln_type,
            "timestamp": timestamp,
            "total_snippets": total_snippets,
            "total_lines": total_lines,
            "total_findings": total_findings,
            "severity_counts": dict(severity_counts),
            "rule_counts": dict(rule_counts),
            "findings_per_snippet": round(total_findings / total_snippets, 2) if total_snippets > 0 else 0,
            "custom_rules_used": len(custom_config.get("--config", [])) if custom_config else 0
        }
    }


def generate_comparison_report(before_data, after_fixing_data, after_fine_tuning_data, output_dir, vuln_type):
    """Generate HTML comparison report with three-way comparison"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    before_stats = before_data["stats"]
    after_fixing_stats = after_fixing_data["stats"]
    after_fine_tuning_stats = after_fine_tuning_data["stats"]
    
    # Calculate all changes
    findings_change_fixing = after_fixing_stats["total_findings"] - before_stats["total_findings"]
    findings_change_fixing_pct = (findings_change_fixing / before_stats["total_findings"] * 100) if before_stats["total_findings"] > 0 else 0
    
    findings_change_tuning = after_fine_tuning_stats["total_findings"] - after_fixing_stats["total_findings"]
    findings_change_tuning_pct = (findings_change_tuning / after_fixing_stats["total_findings"] * 100) if after_fixing_stats["total_findings"] > 0 else 0
    
    findings_change_overall = after_fine_tuning_stats["total_findings"] - before_stats["total_findings"]
    findings_change_overall_pct = (findings_change_overall / before_stats["total_findings"] * 100) if before_stats["total_findings"] > 0 else 0
    
    # Generate HTML sections
    def extract_findings_and_snippets(data):
        findings_detail = []
        snippets = {}
        for result in data["results"]:
            snippet_idx = result.get("snippet_index", "?")
            prompt = result.get("prompt", "")
            code = result.get("code", "")
            snippets[snippet_idx] = {"code": code, "prompt": prompt}
            
            for finding in result.get("results", []):
                findings_detail.append({
                    "snippet_idx": snippet_idx,
                    "prompt": prompt,
                    "rule": finding.get("check_id", ""),
                    "severity": finding.get("extra", {}).get("severity", "unknown"),
                    "message": finding.get("extra", {}).get("message", ""),
                    "line": finding.get("start", {}).get("line", "")
                })
        return findings_detail, snippets
    
    findings_before, snippets_before = extract_findings_and_snippets(before_data)
    findings_fixing, snippets_fixing = extract_findings_and_snippets(after_fixing_data)
    findings_tuning, snippets_tuning = extract_findings_and_snippets(after_fine_tuning_data)
    
    # Severity comparison table
    all_severities = set(before_stats["severity_counts"].keys()) | set(after_fixing_stats["severity_counts"].keys()) | set(after_fine_tuning_stats["severity_counts"].keys())
    severity_rows = []
    for severity in sorted(all_severities):
        b = before_stats["severity_counts"].get(severity, 0)
        f = after_fixing_stats["severity_counts"].get(severity, 0)
        t = after_fine_tuning_stats["severity_counts"].get(severity, 0)
        
        c1 = f - b
        c2 = t - f
        c3 = t - b
        
        c1_str = f"<span style='color:{'red' if c1 > 0 else 'green'}'>{c1:+d}</span>" if c1 != 0 else "0"
        c2_str = f"<span style='color:{'red' if c2 > 0 else 'green'}'>{c2:+d}</span>" if c2 != 0 else "0"
        c3_str = f"<span style='color:{'red' if c3 > 0 else 'green'}'>{c3:+d}</span>" if c3 != 0 else "0"
        
        severity_rows.append(f"<tr><td>{html.escape(severity)}</td><td>{b}</td><td>{f}</td><td>{t}</td><td>{c1_str}</td><td>{c2_str}</td><td>{c3_str}</td></tr>")
    
    # Top rules table
    all_rules = set(before_stats["rule_counts"].keys()) | set(after_fixing_stats["rule_counts"].keys()) | set(after_fine_tuning_stats["rule_counts"].keys())
    rule_changes = []
    for rule in all_rules:
        b = before_stats["rule_counts"].get(rule, 0)
        f = after_fixing_stats["rule_counts"].get(rule, 0)
        t = after_fine_tuning_stats["rule_counts"].get(rule, 0)
        rule_changes.append((rule, b, f, t, f-b, t-f, t-b))
    
    rule_changes.sort(key=lambda x: abs(x[6]), reverse=True)
    rule_rows = []
    for rule, b, f, t, c1, c2, c3 in rule_changes[:15]:
        c1_str = f"<span style='color:{'red' if c1 > 0 else 'green'}'>{c1:+d}</span>" if c1 != 0 else "0"
        c2_str = f"<span style='color:{'red' if c2 > 0 else 'green'}'>{c2:+d}</span>" if c2 != 0 else "0"
        c3_str = f"<span style='color:{'red' if c3 > 0 else 'green'}'>{c3:+d}</span>" if c3 != 0 else "0"
        rule_rows.append(f"<tr><td>{html.escape(rule)}</td><td>{b}</td><td>{f}</td><td>{t}</td><td>{c1_str}</td><td>{c2_str}</td><td>{c3_str}</td></tr>")
    
    # Detailed findings tables
    def group_by_snippet(findings):
        grouped = defaultdict(list)
        for f in findings:
            grouped[f["snippet_idx"]].append(f)
        return grouped
    
    def create_detail_rows(by_snippet, stage_id):
        rows = []
        for snippet_idx in sorted(by_snippet.keys()):
            findings = by_snippet[snippet_idx]
            prompt = findings[0]["prompt"] if findings else ""
            for i, f in enumerate(findings):
                sev_color = {"ERROR": "#d32f2f", "WARNING": "#f57c00", "INFO": "#1976d2"}.get(f["severity"], "#666")
                link = f'<a href="#" onclick="showSnippet(\'{stage_id}\', {snippet_idx}); return false;" style="color:#2196F3;text-decoration:underline;font-weight:bold">#{snippet_idx}</a>'
                rows.append(f"""<tr>
                  {'<td rowspan="' + str(len(findings)) + '">' + link + '</td>' if i == 0 else ''}
                  {'<td rowspan="' + str(len(findings)) + '" style="font-size:12px">' + html.escape(prompt[:80] + '...' if len(prompt) > 80 else prompt) + '</td>' if i == 0 else ''}
                  <td><span style="background:{sev_color};color:white;padding:2px 8px;border-radius:3px;font-size:11px">{html.escape(f["severity"])}</span></td>
                  <td style="font-size:12px">{html.escape(f["rule"])}</td>
                  <td>{f["line"]}</td>
                  <td style="font-size:12px">{html.escape(f["message"][:120] + '...' if len(f["message"]) > 120 else f["message"])}</td>
                </tr>""")
        return rows
    
    before_by_snippet = group_by_snippet(findings_before)
    fixing_by_snippet = group_by_snippet(findings_fixing)
    tuning_by_snippet = group_by_snippet(findings_tuning)
    
    detailed_rows_before = create_detail_rows(before_by_snippet, "before")
    detailed_rows_fixing = create_detail_rows(fixing_by_snippet, "fixing")
    detailed_rows_tuning = create_detail_rows(tuning_by_snippet, "tuning")
    
    # Custom rules info badge
    custom_rules_badge = ""
    custom_rules_count = before_stats.get("custom_rules_used", 0)
    if custom_rules_count > 0:
        custom_rules_badge = f'<span class="vuln-badge" style="background:#9C27B0">+ {custom_rules_count} Custom Rules</span>'
    
    html_report = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Semgrep Analysis - {html.escape(vuln_type)}</title><style>
body{{font-family:sans-serif;margin:20px;background:#f5f5f5}}
.container{{max-width:1600px;margin:0 auto;background:white;padding:30px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}}
h2{{color:#333;border-bottom:3px solid #4CAF50;padding-bottom:10px}}
h3{{color:#555;margin-top:30px}}
.vuln-badge{{display:inline-block;background:#2196F3;color:white;padding:5px 15px;border-radius:20px;font-size:14px;margin-left:10px}}
.stats-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin:20px 0}}
.stat-box{{background:#f9f9f9;padding:20px;border-radius:5px;border-left:4px solid #4CAF50}}
.stat-box h4{{margin:0 0 10px 0;color:#666;font-size:14px;text-transform:uppercase}}
.stat-box .value{{font-size:32px;font-weight:bold;color:#333}}
.stat-box .change{{font-size:16px;margin-top:5px}}
.stat-box .label{{font-size:12px;color:#999;margin-top:3px}}
.positive{{color:#4CAF50}}
.negative{{color:#f44336}}
table{{border-collapse:collapse;width:100%;margin-top:20px;font-size:13px}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}
th{{background:#4CAF50;color:white;font-weight:bold}}
tr:nth-child(even){{background:#f9f9f9}}
tr:hover{{background:#f0f0f0}}
.summary{{background:#e3f2fd;padding:20px;border-radius:5px;margin:20px 0;border-left:4px solid #2196F3}}
.tabs{{display:flex;gap:10px;margin:20px 0;border-bottom:2px solid #ddd}}
.tab{{padding:10px 20px;cursor:pointer;border:none;background:none;font-size:16px;font-weight:bold;color:#666}}
.tab.active{{color:#4CAF50;border-bottom:3px solid #4CAF50;margin-bottom:-2px}}
.tab-content{{display:none}}
.tab-content.active{{display:block}}
.modal{{display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.7);overflow:auto}}
.modal-content{{background:white;margin:2% auto;padding:0;width:90%;max-width:1200px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.3)}}
.modal-header{{background:#4CAF50;color:white;padding:20px;border-radius:8px 8px 0 0}}
.modal-body{{padding:20px;max-height:70vh;overflow-y:auto}}
.close{{color:white;float:right;font-size:32px;font-weight:bold;cursor:pointer;line-height:20px}}
.close:hover{{color:#ddd}}
pre{{background:#f5f5f5;padding:15px;border-radius:5px;overflow-x:auto;border-left:4px solid #4CAF50;line-height:1.6}}
code{{font-family:'Courier New',monospace;font-size:13px}}
.line-numbers{{counter-reset:line}}
.line-numbers .line{{counter-increment:line}}
.line-numbers .line:before{{content:counter(line);display:inline-block;width:40px;padding-right:10px;color:#999;text-align:right;border-right:2px solid #ddd;margin-right:10px}}
.comparison-box{{background:#fff3cd;padding:15px;border-radius:5px;margin:10px 0;border-left:4px solid:#ffc107}}
.comparison-box h4{{margin:0 0 10px 0;color:#856404}}
</style>
<script>
const snippetsBefore = {json.dumps({str(k): v for k, v in snippets_before.items()})};
const snippetsFixing = {json.dumps({str(k): v for k, v in snippets_fixing.items()})};
const snippetsTuning = {json.dumps({str(k): v for k, v in snippets_tuning.items()})};

function showTab(tabName) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById(tabName).classList.add('active');
  document.querySelector('[onclick="showTab(\\'' + tabName + '\\')"]').classList.add('active');
}}

function showSnippet(type, idx) {{
  let snippets, stageLabel;
  if (type === 'before') {{ snippets = snippetsBefore; stageLabel = 'Raw/Before'; }}
  else if (type === 'fixing') {{ snippets = snippetsFixing; stageLabel = 'After Fixing'; }}
  else {{ snippets = snippetsTuning; stageLabel = 'After Fine-Tuning'; }}
  
  const snippet = snippets[idx];
  if (!snippet) {{ alert('Snippet not found'); return; }}
  
  const modal = document.getElementById('snippetModal');
  const title = document.getElementById('modalTitle');
  const code = document.getElementById('modalCode');
  
  title.textContent = stageLabel + ' - Snippet #' + idx;
  
  const lines = snippet.code.split('\\n');
  const numberedCode = lines.map(line => 
    '<div class="line"><span>' + line.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</span></div>'
  ).join('');
  
  code.innerHTML = '<div style="margin-bottom:15px;padding:10px;background:#e3f2fd;border-radius:5px"><strong>Prompt:</strong> ' + 
    snippet.prompt.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</div>' +
    '<pre class="line-numbers"><code>' + numberedCode + '</code></pre>';
  
  modal.style.display = 'block';
}}

function closeModal() {{ document.getElementById('snippetModal').style.display = 'none'; }}

window.onclick = function(event) {{
  if (event.target == document.getElementById('snippetModal')) closeModal();
}}
</script>
</head><body>
<div class="container">
<h2>🔒 Semgrep Security Analysis: Three-Stage Comparison<span class="vuln-badge">{html.escape(vuln_type.upper())}</span>{custom_rules_badge}</h2>

<div class="summary">
<p><b>Vulnerability Type:</b> {html.escape(vuln_type)}<br>
<b>Analysis Date:</b> {timestamp}<br>
<b>Custom Rules Used:</b> {custom_rules_count}<br>
<b>Stage 1 (Raw):</b> {before_stats['total_snippets']} snippets<br>
<b>Stage 2 (Fixed):</b> {after_fixing_stats['total_snippets']} snippets<br>
<b>Stage 3 (Fine-Tuned):</b> {after_fine_tuning_stats['total_snippets']} snippets</p>
</div>

<h3>📊 Overall Impact</h3>
<div class="stats-grid">
  <div class="stat-box" style="border-left-color:#f44336">
    <h4>Stage 1: Raw</h4>
    <div class="value">{before_stats['total_findings']}</div>
    <div style="font-size:14px;color:#666;margin-top:5px">{before_stats['findings_per_snippet']:.2f} avg/snippet</div>
  </div>
  <div class="stat-box" style="border-left-color:#ff9800">
    <h4>Stage 2: Fixed</h4>
    <div class="value">{after_fixing_stats['total_findings']}</div>
    <div class="change {'negative' if findings_change_fixing > 0 else 'positive'}">{findings_change_fixing:+d} ({findings_change_fixing_pct:+.1f}%)</div>
    <div class="label">vs Raw</div>
  </div>
  <div class="stat-box" style="border-left-color:#4CAF50">
    <h4>Stage 3: Fine-Tuned</h4>
    <div class="value">{after_fine_tuning_stats['total_findings']}</div>
    <div class="change {'negative' if findings_change_tuning > 0 else 'positive'}">{findings_change_tuning:+d} ({findings_change_tuning_pct:+.1f}%)</div>
    <div class="label">vs Fixed</div>
  </div>
</div>

<div class="comparison-box">
  <h4>🎯 Key Comparisons</h4>
  <p><b>Raw → Fixed:</b> <span class="{'negative' if findings_change_fixing > 0 else 'positive'}">{findings_change_fixing:+d} ({findings_change_fixing_pct:+.1f}%)</span></p>
  <p><b>Fixed → Fine-Tuned:</b> <span class="{'negative' if findings_change_tuning > 0 else 'positive'}">{findings_change_tuning:+d} ({findings_change_tuning_pct:+.1f}%)</span></p>
  <p><b>Raw → Fine-Tuned (Overall):</b> <span class="{'negative' if findings_change_overall > 0 else 'positive'}">{findings_change_overall:+d} ({findings_change_overall_pct:+.1f}%)</span></p>
</div>

<h3>⚠️ Findings by Severity</h3>
<table>
<tr><th rowspan="2">Severity</th><th colspan="3">Counts</th><th colspan="3">Changes</th></tr>
<tr><th>Raw</th><th>Fixed</th><th>Fine-Tuned</th><th>Raw→Fixed</th><th>Fixed→Tuned</th><th>Raw→Tuned</th></tr>
{''.join(severity_rows) if severity_rows else '<tr><td colspan="7" style="text-align:center">No data</td></tr>'}
</table>

<h3>🎯 Top Security Rules</h3>
<table>
<tr><th rowspan="2">Rule ID</th><th colspan="3">Counts</th><th colspan="3">Changes</th></tr>
<tr><th>Raw</th><th>Fixed</th><th>Fine-Tuned</th><th>Raw→Fixed</th><th>Fixed→Tuned</th><th>Raw→Tuned</th></tr>
{''.join(rule_rows) if rule_rows else '<tr><td colspan="7" style="text-align:center">No data</td></tr>'}
</table>

<h3>🔍 Detailed Findings</h3>
<div class="tabs">
  <button class="tab active" onclick="showTab('before-details')">Stage 1: Raw</button>
  <button class="tab" onclick="showTab('fixing-details')">Stage 2: Fixed</button>
  <button class="tab" onclick="showTab('tuning-details')">Stage 3: Fine-Tuned</button>
</div>

<div id="before-details" class="tab-content active">
  <table>
    <tr><th>Snippet</th><th>Prompt</th><th>Severity</th><th>Rule</th><th>Line</th><th>Message</th></tr>
    {''.join(detailed_rows_before) if detailed_rows_before else '<tr><td colspan="6" style="text-align:center;color:#4CAF50">✓ No findings</td></tr>'}
  </table>
</div>

<div id="fixing-details" class="tab-content">
  <table>
    <tr><th>Snippet</th><th>Prompt</th><th>Severity</th><th>Rule</th><th>Line</th><th>Message</th></tr>
    {''.join(detailed_rows_fixing) if detailed_rows_fixing else '<tr><td colspan="6" style="text-align:center;color:#4CAF50">✓ No findings</td></tr>'}
  </table>
</div>

<div id="tuning-details" class="tab-content">
  <table>
    <tr><th>Snippet</th><th>Prompt</th><th>Severity</th><th>Rule</th><th>Line</th><th>Message</th></tr>
    {''.join(detailed_rows_tuning) if detailed_rows_tuning else '<tr><td colspan="6" style="text-align:center;color:#4CAF50">✓ No findings</td></tr>'}
  </table>
</div>

<h3>📈 Interpretation</h3>
<div class="summary">
<h4>Raw → Fixed:</h4>
{'<p style="color:#4CAF50"><b>✓ Improvement:</b> Fixing reduced findings by ' + str(abs(findings_change_fixing)) + ' (' + f'{abs(findings_change_fixing_pct):.1f}%' + ').</p>' if findings_change_fixing < 0 else ''}
{'<p style="color:#f44336"><b>⚠ Regression:</b> Fixing increased findings by ' + str(findings_change_fixing) + ' (' + f'{findings_change_fixing_pct:.1f}%' + ').</p>' if findings_change_fixing > 0 else ''}
{'<p style="color:#666"><b>→ No Change</b></p>' if findings_change_fixing == 0 else ''}

<h4>Fixed → Fine-Tuned:</h4>
{'<p style="color:#4CAF50"><b>✓ Improvement:</b> Fine-tuning reduced findings by ' + str(abs(findings_change_tuning)) + ' (' + f'{abs(findings_change_tuning_pct):.1f}%' + ').</p>' if findings_change_tuning < 0 else ''}
{'<p style="color:#f44336"><b>⚠ Regression:</b> Fine-tuning increased findings by ' + str(findings_change_tuning) + ' (' + f'{findings_change_tuning_pct:.1f}%' + ').</p>' if findings_change_tuning > 0 else ''}
{'<p style="color:#666"><b>→ No Change</b></p>' if findings_change_tuning == 0 else ''}

<h4>Raw → Fine-Tuned (Overall):</h4>
{'<p style="color:#4CAF50"><b>✓ Overall Improvement:</b> Total reduction of ' + str(abs(findings_change_overall)) + ' findings (' + f'{abs(findings_change_overall_pct):.1f}%' + ').</p>' if findings_change_overall < 0 else ''}
{'<p style="color:#f44336"><b>⚠ Overall Regression:</b> Total increase of ' + str(findings_change_overall) + ' findings (' + f'{findings_change_overall_pct:.1f}%' + ').</p>' if findings_change_overall > 0 else ''}
{'<p style="color:#666"><b>→ No Overall Change</b></p>' if findings_change_overall == 0 else ''}
</div>

</div>

<div id="snippetModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <span class="close" onclick="closeModal()">&times;</span>
      <h2 id="modalTitle" style="margin:0">Code Snippet</h2>
    </div>
    <div class="modal-body">
      <div id="modalCode"></div>
    </div>
  </div>
</div>

</body></html>"""
    
    report_path = os.path.join(output_dir, f"{vuln_type}_comparison_report_{timestamp}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    
    json_path = os.path.join(output_dir, f"{vuln_type}_comparison_data_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump({
            "vuln_type": vuln_type,
            "before": before_data,
            "after_fixing": after_fixing_data,
            "after_fine_tuning": after_fine_tuning_data,
            "comparison_timestamp": timestamp,
            "changes": {
                "raw_to_fixing": {"findings": findings_change_fixing, "findings_pct": findings_change_fixing_pct},
                "fixing_to_tuning": {"findings": findings_change_tuning, "findings_pct": findings_change_tuning_pct},
                "raw_to_tuning_overall": {"findings": findings_change_overall, "findings_pct": findings_change_overall_pct}
            }
        }, f, indent=2)
    
    return report_path, json_path

def serve_reports(base_dir="semgrep_results", port=5050):
   """Serve all scan folders and their reports for browsing."""
   app = Flask(__name__)

   @app.route("/")
   def index():
      scans = sorted(
         [d for d in glob.glob(os.path.join(base_dir, "scan_*")) if os.path.isdir(d)],
         reverse=True
      )
      items = []
      for scan_dir in scans:
         reports = sorted(glob.glob(os.path.join(scan_dir, "*_comparison_report_*.html")), reverse=True)
         rel = os.path.relpath(scan_dir, base_dir)
         links = "".join(
            f"<li><a href='/report/{rel}/{os.path.basename(r)}'>{os.path.basename(r)}</a></li>"
            for r in reports
         )
         items.append(f"<h3>📂 {rel}</h3><ul>{links or '<li><i>No reports</i></li>'}</ul>")

      html = f"""
      <html><head><title>Semgrep Reports Viewer</title></head>
      <body style='font-family:sans-serif;padding:30px;background:#f5f5f5'>
         <h2>📊 Semgrep Scan Reports</h2>
         {'<br>'.join(items) if items else '<p>No results yet.</p>'}
         <hr><p style='color:#666'>Base directory: {base_dir}</p>
      </body></html>
      """
      return render_template_string(html)

   @app.route("/report/<path:subdir>/<path:filename>")
   def report(subdir, filename):
      folder = os.path.join(base_dir, subdir)
      return send_from_directory(folder, filename)

   def run_server():
      print(f"\n🚀 Flask viewer running at http://127.0.0.1:{port}")
      app.run(port=port, debug=False, use_reloader=False)

   threading.Thread(target=run_server, daemon=True).start()
   webbrowser.open(f"http://127.0.0.1:{port}")

   """Start a small Flask server to browse and view reports interactively."""
   app = Flask(__name__)

   @app.route("/")
   def index():
      output_dir = "semgrep_results"
      files = sorted(glob.glob(os.path.join(output_dir, "*_comparison_report_*.html")), reverse=True)
      links = [f"<li><a href='/report/{os.path.basename(f)}'>{os.path.basename(f)}</a></li>" for f in files]
      html = f"""
      <html><head><title>Semgrep Reports</title></head>
      <body style='font-family:sans-serif;padding:30px'>
      <h2>📊 Available Reports ({len(files)})</h2>
      <ul>{''.join(links)}</ul>
      <p style='margin-top:20px;color:#555'>Serving directory: {output_dir}</p>
      </body></html>
      """
      return render_template_string(html)

   @app.route("/report/<path:filename>")
   def report(filename):
      return send_from_directory(output_dir, filename)

   def run_server():
      print(f"\n🚀 Flask viewer running at http://127.0.0.1:{port}")
      app.run(port=port, debug=False, use_reloader=False)

   threading.Thread(target=run_server, daemon=True).start()


# ============= MAIN EXECUTION =============
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Semgrep 3-stage comparison tool")
    parser.add_argument("mode", choices=["scan", "serve", "single"], help="scan: run full analysis, serve: launch report viewer")
    parser.add_argument("--out", default=None, help="output directory to serve or save results to")
    parser.add_argument("--port", type=int, default=5050, help="port for Flask server (serve mode)")
    parser.add_argument("--custom", type=bool, default=False, help="custom semgrep rules")
    args = parser.parse_args()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    OUT_DIR = f"semgrep_results/scan_{timestamp}"
    

    if args.mode == "serve":
        base_dir = args.out or "semgrep_results"
        if not os.path.isdir(base_dir):
            print(f"Directory not found: {base_dir}")
            exit(1)
        print(f"Serving all reports from base directory: {base_dir}")
        serve_reports(base_dir, args.port)
        input("\nPress Enter to stop the server...\n")    
    else:
        os.makedirs(OUT_DIR, exist_ok=True)
        # Load configuration
        config = load_vuln_config()
        
        # Load custom semgrep configuration
        custom_config = load_custom_semgrep_config(CUSTOM_CONFIG_PATH)
        
        # Set to None to scan all snippets, or a number to limit
        MAX_SNIPPETS = 180  # Remove or set to None for full scan

        print("="*60)
        print("SEMGREP THREE-STAGE COMPARISON (PER VULNERABILITY)")
        #if custom_config:
        #    print(f"Using {len(custom_config.get('--config', []))} custom rule(s)")
        print("="*60)

        all_results = {}

        # Process each vulnerability type separately
        for vuln_type, paths in config.items():
            print(f"\n{'='*60}")
            print(f"Processing vulnerability: {vuln_type.upper()}")
            print(f"{'='*60}")
            
            before_path = paths["before"]
            fixed_path = paths["fixed"]
            fine_tuned_path = paths["fine_tuned"]

            # Scan Stage 1: BEFORE
            print(f"\n[1/4] Scanning BEFORE for {vuln_type}...")
            #before_data = scan_jsonl_file(before_path, OUT_DIR, "before", vuln_type, custom_config, MAX_SNIPPETS)
            before_data = scan_jsonl_file(before_path, OUT_DIR, "before", vuln_type, None, MAX_SNIPPETS)

            # Scan Stage 2: AFTER FIXING
            print(f"\n[2/4] Scanning AFTER FIXING for {vuln_type}...")
            #after_fixing_data = scan_jsonl_file(fixed_path, OUT_DIR, "fixed", vuln_type, custom_config, MAX_SNIPPETS)
            after_fixing_data = scan_jsonl_file(fixed_path, OUT_DIR, "fixed", vuln_type, None, MAX_SNIPPETS)

            # Scan Stage 3: AFTER FINE-TUNING
            print(f"\n[3/4] Scanning AFTER FINE-TUNING for {vuln_type}...")
            #after_fine_tuning_data = scan_jsonl_file(fine_tuned_path, OUT_DIR, "fine_tuned", vuln_type, custom_config, MAX_SNIPPETS)
            after_fine_tuning_data = scan_jsonl_file(fine_tuned_path, OUT_DIR, "fine_tuned", vuln_type, None, MAX_SNIPPETS)

            # Generate comparison report for this vulnerability
            print(f"\n[4/4] Generating comparison report for {vuln_type}...")
            report_path, json_path = generate_comparison_report(
                before_data, 
                after_fixing_data, 
                after_fine_tuning_data, 
                OUT_DIR, 
                vuln_type
            )

            # Store results
            all_results[vuln_type] = {
                "report_path": report_path,
                "json_path": json_path,
                "before_findings": before_data['stats']['total_findings'],
                "fixing_findings": after_fixing_data['stats']['total_findings'],
                "tuning_findings": after_fine_tuning_data['stats']['total_findings']
            }

            # Print summary for this vulnerability
            print(f"\n{'='*60}")
            print(f"✓ Report for {vuln_type} saved: {report_path}")
            print(f"✓ JSON data saved: {json_path}")
            print(f"\n📊 Quick Summary for {vuln_type}:")
            print(f"  Raw:        {before_data['stats']['total_findings']} findings ({before_data['stats']['findings_per_snippet']:.2f} avg)")
            print(f"  Fixed:      {after_fixing_data['stats']['total_findings']} findings ({after_fixing_data['stats']['findings_per_snippet']:.2f} avg)")
            print(f"  Fine-Tuned: {after_fine_tuning_data['stats']['total_findings']} findings ({after_fine_tuning_data['stats']['findings_per_snippet']:.2f} avg)")
            
            change_fixing = after_fixing_data['stats']['total_findings'] - before_data['stats']['total_findings']
            change_tuning = after_fine_tuning_data['stats']['total_findings'] - after_fixing_data['stats']['total_findings']
            change_overall = after_fine_tuning_data['stats']['total_findings'] - before_data['stats']['total_findings']
            
            if before_data['stats']['total_findings'] > 0:
                print(f"  Raw → Fixed:      {change_fixing:+d} ({change_fixing/before_data['stats']['total_findings']*100:+.1f}%)")
            if after_fixing_data['stats']['total_findings'] > 0:
                print(f"  Fixed → Tuned:    {change_tuning:+d} ({change_tuning/after_fixing_data['stats']['total_findings']*100:+.1f}%)")
            if before_data['stats']['total_findings'] > 0:
                print(f"  Raw → Tuned:      {change_overall:+d} ({change_overall/before_data['stats']['total_findings']*100:+.1f}%)")
            print(f"{'='*60}")

        # Print overall summary
        print(f"\n\n{'='*60}")
        print("OVERALL SUMMARY - ALL VULNERABILITIES")
        print(f"{'='*60}")
        print(f"\nTotal vulnerabilities processed: {len(all_results)}")
        print(f"Output directory: {OUT_DIR}\n")
        
        total_before = sum(r['before_findings'] for r in all_results.values())
        total_fixing = sum(r['fixing_findings'] for r in all_results.values())
        total_tuning = sum(r['tuning_findings'] for r in all_results.values())
        
        print(f"Aggregate findings across all vulnerabilities:")
        print(f"  Raw:        {total_before} findings")
        print(f"  Fixed:      {total_fixing} findings")
        print(f"  Fine-Tuned: {total_tuning} findings")
        
        if total_before > 0:
            print(f"\nAggregate changes:")
            print(f"  Raw → Fixed:      {total_fixing - total_before:+d} ({(total_fixing - total_before)/total_before*100:+.1f}%)")
            if total_fixing > 0:
                print(f"  Fixed → Tuned:    {total_tuning - total_fixing:+d} ({(total_tuning - total_fixing)/total_fixing*100:+.1f}%)")
            print(f"  Raw → Tuned:      {total_tuning - total_before:+d} ({(total_tuning - total_before)/total_before*100:+.1f}%)")
        
        print(f"\n📁 Individual reports generated:")
        for vuln_type, result in all_results.items():
            print(f"  • {vuln_type}: {result['report_path']}")
        
        print(f"\n{'='*60}")
        print("✓ Analysis complete!")
        print(f"{'='*60}\n")