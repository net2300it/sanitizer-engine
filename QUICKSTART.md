# Yara-X Sanitizer Engine - Quick Start Guide

## 5-Minute Setup

### 1. Install Dependencies

```bash
pip install yara-x flask
```

### 2. Create Your First Scanner

```python
# my_scanner.py
from yara_scanner import YaraXScanner

# Initialize with rules
scanner = YaraXScanner(rules_path="./example_rules.yar")

# Scan a file
result = scanner.scan_file("suspicious_file.exe")

if result.is_malicious:
    print(f"⚠️  THREAT DETECTED!")
    print(f"Matches: {len(result.matches)}")
    for match in result.matches:
        print(f"  • {match.rule_name}")
else:
    print("✓ File is clean")
```

### 3. Run It

```bash
python my_scanner.py
```

## Common Use Cases

### Web Upload Scanner

```python
from flask import Flask, request
from sanitizer_integration import SanitizerYaraIntegration, SanitizerConfig

app = Flask(__name__)

# Setup sanitizer
config = SanitizerConfig(rules_path="./rules")
sanitizer = SanitizerYaraIntegration(config)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    
    # Scan before saving
    result = sanitizer.scan_upload(file.read(), file.filename)
    
    if result['safe']:
        return {'status': 'accepted'}
    else:
        return {'status': 'rejected', 'reason': result['message']}, 403

app.run()
```

### Batch File Scanner

```python
from pathlib import Path
from yara_scanner import YaraXScanner

scanner = YaraXScanner(rules_path="./rules")

# Scan all files in a directory
downloads = Path.home() / "Downloads"
results = scanner.scan_directory(downloads, recursive=True)

# Report findings
threats = [r for r in results if r.is_malicious]
print(f"Scanned {len(results)} files")
print(f"Found {len(threats)} threats")

for threat in threats:
    print(f"⚠️  {threat.file_path}")
```

### Memory Scanner

```python
from yara_scanner import YaraXScanner

scanner = YaraXScanner(rules_path="./rules")

# Scan data in memory (no file needed)
suspicious_data = b"some suspicious content"
result = scanner.scan_data(suspicious_data, identifier="network_packet")

if result.is_malicious:
    print("Malicious data detected!")
```

## Docker Quick Start

```bash
# Build
docker build -t sanitizer-engine .

# Run
docker run -p 5000:5000 \
  -v $(pwd)/rules:/app/rules \
  -v $(pwd)/quarantine:/app/quarantine \
  sanitizer-engine

# Test
curl -X POST http://localhost:5000/scan/file \
  -F "file=@test.exe"
```

## Writing Custom Rules

Create `custom_rules.yar`:

```yara
rule MyCustomRule
{
    meta:
        author = "Your Name"
        description = "Detects XYZ malware"
        severity = "high"
    
    strings:
        $pattern1 = "malicious_string"
        $pattern2 = { 4D 5A 90 00 }  // Hex pattern
    
    condition:
        $pattern1 or $pattern2
}
```

Use it:

```python
scanner = YaraXScanner(rules_path="./custom_rules.yar")
```

## API Testing with curl

```bash
# Health check
curl http://localhost:5000/health

# Upload scan
curl -X POST http://localhost:5000/scan/file \
  -F "file=@/path/to/file.exe"

# Path scan
curl -X POST http://localhost:5000/scan/path \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/suspicious.bin"}'

# Statistics
curl http://localhost:5000/stats
```

## Next Steps

1. **Add more rules**: Download rule sets from:
   - [Yara-Rules GitHub](https://github.com/Yara-Rules/rules)
   - [VirusTotal Yara](https://github.com/VirusTotal/yara)

2. **Customize configuration**: Edit threat levels and actions

3. **Integrate with your app**: Use the Python API or REST endpoints

4. **Monitor activity**: Check logs and statistics

## Troubleshooting

**Issue**: `ImportError: No module named 'yara_x'`
```bash
pip install yara-x
```

**Issue**: Rules not loading
```bash
# Check rule syntax
python -c "import yara_x; yara_x.Compiler().add_source(open('rules.yar').read())"
```

**Issue**: Permission denied on quarantine
```bash
chmod 755 quarantine/
```

## Support

- 📖 Full docs: See `README.md`
- 🐛 Issues: GitHub Issues
- 💬 Questions: Open a discussion

Happy scanning! 🛡️
