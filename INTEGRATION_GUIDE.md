# Integrating Yara-X into Sanitizer Engine

This guide shows you how to integrate the Yara-X scanner into your existing sanitizer-engine project.

## Integration Overview

The Yara-X integration provides:
- **File scanning** before processing
- **Upload validation** to block malicious files
- **Automatic quarantine** of detected threats
- **REST API endpoints** for scanning
- **Configurable threat responses**

## Step-by-Step Integration

### Step 1: Add Files to Your Project

Copy these files to your sanitizer-engine project:

```
sanitizer-engine/
├── yara_scanner.py           # Core Yara-X scanner
├── sanitizer_integration.py  # Integration layer
├── sanitizer_api.py          # REST API (optional)
├── requirements.txt          # Dependencies
├── example_rules.yar         # Sample Yara rules
└── rules/                    # Your Yara rules directory
```

### Step 2: Install Dependencies

```bash
cd sanitizer-engine
pip install -r requirements.txt
```

### Step 3: Basic Integration

Add to your existing sanitizer code:

```python
from sanitizer_integration import SanitizerYaraIntegration, SanitizerConfig

# Initialize Yara scanner
yara_config = SanitizerConfig(
    rules_path="./rules",
    quarantine_dir="/var/quarantine",
    enable_auto_quarantine=True,
    scan_timeout=60
)

yara_scanner = SanitizerYaraIntegration(yara_config)

# Use in your sanitizer
def sanitize_file(file_path):
    # First, scan with Yara
    scan_result = yara_scanner.sanitize_file(file_path)
    
    if not scan_result['safe']:
        logger.warning(f"Malware detected: {file_path}")
        return False
    
    # Continue with your existing sanitization
    # ... your code here ...
    
    return True
```

### Step 4: Add Upload Scanning

For file uploads in your web application:

```python
from flask import request
from sanitizer_integration import SanitizerYaraIntegration, SanitizerConfig

yara_scanner = SanitizerYaraIntegration(SanitizerConfig(rules_path="./rules"))

@app.route('/upload', methods=['POST'])
def handle_upload():
    file = request.files['file']
    file_data = file.read()
    
    # Scan before processing
    result = yara_scanner.scan_upload(file_data, file.filename)
    
    if not result['safe']:
        return jsonify({
            'error': 'Malicious file detected',
            'details': result['message']
        }), 403
    
    # Continue with file processing
    # ... your code here ...
```

### Step 5: Directory Monitoring

Add background scanning for incoming directories:

```python
import time
from pathlib import Path
from sanitizer_integration import SanitizerYaraIntegration, SanitizerConfig

def monitor_directory(watch_path, interval=60):
    """Monitor directory and scan new files."""
    yara_scanner = SanitizerYaraIntegration(SanitizerConfig(rules_path="./rules"))
    seen_files = set()
    
    while True:
        current_files = set(Path(watch_path).rglob("*"))
        new_files = current_files - seen_files
        
        for file_path in new_files:
            if file_path.is_file():
                result = yara_scanner.sanitize_file(file_path)
                if not result['safe']:
                    logger.warning(f"Threat found: {file_path}")
        
        seen_files = current_files
        time.sleep(interval)

# Run in background
import threading
monitor_thread = threading.Thread(
    target=monitor_directory,
    args=("/path/to/incoming",),
    daemon=True
)
monitor_thread.start()
```

## Advanced Integration Patterns

### Pattern 1: Pipeline Integration

```python
class SanitizerPipeline:
    def __init__(self):
        self.yara_scanner = SanitizerYaraIntegration(
            SanitizerConfig(rules_path="./rules")
        )
        # ... other sanitizers ...
    
    def process_file(self, file_path):
        """Process file through sanitization pipeline."""
        
        # Step 1: Yara scan
        yara_result = self.yara_scanner.sanitize_file(file_path)
        if not yara_result['safe']:
            return {'status': 'rejected', 'reason': 'malware'}
        
        # Step 2: Format validation
        # ... your code ...
        
        # Step 3: Content sanitization
        # ... your code ...
        
        return {'status': 'success'}
```

### Pattern 2: Event-Driven Integration

```python
from sanitizer_integration import SanitizerYaraIntegration, SanitizerConfig, ThreatLevel

class ThreatHandler:
    def on_threat_detected(self, file_path, scan_result, threat_level):
        """Handle detected threats."""
        if threat_level == ThreatLevel.CRITICAL:
            # Send alert
            self.send_alert(file_path, scan_result)
            # Log to SIEM
            self.log_to_siem(file_path, scan_result)
        
        # Log all threats
        logger.warning(f"Threat: {file_path} - Level: {threat_level.value}")

# Use with custom configuration
config = SanitizerConfig(
    rules_path="./rules",
    threat_actions={
        ThreatLevel.CRITICAL: ['quarantine', 'notify', 'log'],
        ThreatLevel.HIGH: ['quarantine', 'log'],
        ThreatLevel.MEDIUM: ['log'],
    }
)
```

### Pattern 3: Database Integration

```python
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = 'scan_records'
    
    id = Column(Integer, primary_key=True)
    file_path = Column(String)
    file_hash = Column(String)
    scan_date = Column(DateTime, default=datetime.utcnow)
    is_malicious = Column(Boolean)
    threat_level = Column(String)
    rules_matched = Column(String)

def scan_and_record(file_path):
    """Scan file and record in database."""
    yara_scanner = SanitizerYaraIntegration(SanitizerConfig(rules_path="./rules"))
    result = yara_scanner.sanitize_file(file_path)
    
    # Calculate file hash
    import hashlib
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Record scan
    record = ScanRecord(
        file_path=str(file_path),
        file_hash=file_hash,
        is_malicious=not result['safe'],
        threat_level=result.get('threat_level', 'none'),
        rules_matched=','.join(result.get('scan_details', {}).get('rules_matched', []))
    )
    
    session.add(record)
    session.commit()
    
    return result
```

## Configuration Examples

### Development Configuration

```python
from sanitizer_integration import SanitizerConfig

dev_config = SanitizerConfig(
    rules_path="./rules/dev",
    quarantine_dir="/tmp/quarantine",
    enable_auto_quarantine=False,  # Manual review in dev
    scan_timeout=120,
    max_file_size=500 * 1024 * 1024,  # 500MB for testing
    excluded_extensions=['.txt', '.md', '.log']
)
```

### Production Configuration

```python
prod_config = SanitizerConfig(
    rules_path="/etc/sanitizer/rules",
    quarantine_dir="/var/sanitizer/quarantine",
    enable_auto_quarantine=True,
    scan_timeout=30,
    max_file_size=100 * 1024 * 1024,  # 100MB limit
    excluded_extensions=[],  # Scan everything
    threat_actions={
        ThreatLevel.CRITICAL: [
            ScanAction.QUARANTINE,
            ScanAction.LOG,
            ScanAction.NOTIFY,
            ScanAction.BLOCK
        ],
        ThreatLevel.HIGH: [
            ScanAction.QUARANTINE,
            ScanAction.LOG,
            ScanAction.NOTIFY
        ],
        ThreatLevel.MEDIUM: [
            ScanAction.LOG,
            ScanAction.NOTIFY
        ],
        ThreatLevel.LOW: [ScanAction.LOG],
    }
)
```

## Testing Your Integration

### Unit Tests

```python
# test_integration.py
import pytest
from sanitizer_integration import SanitizerYaraIntegration, SanitizerConfig

def test_sanitizer_integration():
    config = SanitizerConfig(rules_path="./test_rules.yar")
    sanitizer = SanitizerYaraIntegration(config)
    
    # Test malicious file
    result = sanitizer.sanitize_file("test_files/malware.exe")
    assert result['safe'] is False
    assert 'threat_level' in result
    
    # Test clean file
    result = sanitizer.sanitize_file("test_files/clean.txt")
    assert result['safe'] is True
```

### Integration Tests

```bash
# Test the full pipeline
pytest tests/test_integration.py -v

# Test API endpoints
pytest tests/test_api.py -v

# Test with real files
python test_integration.py --test-files ./samples
```

## Monitoring and Logging

### Setup Logging

```python
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
handler = RotatingFileHandler(
    'sanitizer.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)

logger = logging.getLogger('sanitizer')
logger.addHandler(handler)
logger.setLevel(logging.INFO)
```

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram, start_http_server

# Define metrics
files_scanned = Counter('sanitizer_files_scanned_total', 'Total files scanned')
threats_detected = Counter('sanitizer_threats_detected_total', 'Total threats detected')
scan_duration = Histogram('sanitizer_scan_duration_seconds', 'Scan duration')

def scan_with_metrics(file_path):
    with scan_duration.time():
        result = yara_scanner.sanitize_file(file_path)
    
    files_scanned.inc()
    if not result['safe']:
        threats_detected.inc()
    
    return result

# Start metrics server
start_http_server(9090)
```

## Performance Optimization

### Optimize Rule Loading

```python
# Load rules once at startup
class SanitizerService:
    def __init__(self):
        self.yara_scanner = SanitizerYaraIntegration(
            SanitizerConfig(rules_path="./rules")
        )
    
    def scan(self, file_path):
        # Reuse the same scanner instance
        return self.yara_scanner.sanitize_file(file_path)

# Create singleton
sanitizer_service = SanitizerService()
```

### Async Scanning

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

class AsyncSanitizer:
    def __init__(self):
        self.yara_scanner = SanitizerYaraIntegration(
            SanitizerConfig(rules_path="./rules")
        )
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def scan_async(self, file_path):
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.executor,
            self.yara_scanner.sanitize_file,
            file_path
        )
        return result

# Use it
async def scan_files(file_paths):
    sanitizer = AsyncSanitizer()
    tasks = [sanitizer.scan_async(fp) for fp in file_paths]
    results = await asyncio.gather(*tasks)
    return results
```

## Troubleshooting

### Common Issues

1. **Rules not loading**
   ```python
   # Verify rules path
   import os
   print(os.path.exists(config.rules_path))
   
   # Check rule syntax
   from yara_scanner import YaraXScanner
   scanner = YaraXScanner(config.rules_path)
   ```

2. **Performance issues**
   ```python
   # Increase timeout
   config.scan_timeout = 120
   
   # Limit file size
   config.max_file_size = 50 * 1024 * 1024
   ```

3. **Quarantine permissions**
   ```bash
   sudo chown -R sanitizer:sanitizer /var/quarantine
   sudo chmod 755 /var/quarantine
   ```

## Next Steps

1. Add your Yara rules to the `rules/` directory
2. Test with sample malware (use test files, not real malware!)
3. Configure threat actions for your environment
4. Set up monitoring and alerting
5. Deploy to production with proper security

## Support

- Check the main `README.md` for detailed documentation
- See `QUICKSTART.md` for quick examples
- Review test files for usage patterns

Happy sanitizing! 🛡️
