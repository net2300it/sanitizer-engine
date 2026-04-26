"""
Unit tests for Yara-X Scanner
"""

import pytest
import tempfile
from pathlib import Path
from yara_scanner import YaraXScanner, YaraMatch, ScanResult


@pytest.fixture
def sample_rules_file():
    """Create a temporary Yara rules file for testing."""
    rules_content = """
    rule TestRule
    {
        meta:
            description = "Test rule"
            severity = "high"
        
        strings:
            $test = "MALICIOUS"
        
        condition:
            $test
    }
    
    rule CleanRule
    {
        meta:
            description = "Benign pattern"
        
        strings:
            $clean = "SAFE"
        
        condition:
            $clean
    }
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
        f.write(rules_content)
        rules_path = f.name
    
    yield rules_path
    
    # Cleanup
    Path(rules_path).unlink()


@pytest.fixture
def scanner(sample_rules_file):
    """Create a scanner instance for testing."""
    return YaraXScanner(sample_rules_file)


def test_scanner_initialization(sample_rules_file):
    """Test scanner initialization."""
    scanner = YaraXScanner(sample_rules_file)
    assert scanner is not None
    assert scanner.scanner is not None


def test_scan_malicious_data(scanner):
    """Test scanning malicious data."""
    data = b"This file contains MALICIOUS content"
    result = scanner.scan_data(data, "test_file")
    
    assert isinstance(result, ScanResult)
    assert result.is_malicious is True
    assert len(result.matches) > 0
    assert result.matches[0].rule_name == "TestRule"


def test_scan_clean_data(scanner):
    """Test scanning clean data."""
    data = b"This is completely harmless content"
    result = scanner.scan_data(data, "clean_file")
    
    assert isinstance(result, ScanResult)
    assert result.is_malicious is False
    assert len(result.matches) == 0


def test_scan_file_malicious(scanner):
    """Test scanning a malicious file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("This contains MALICIOUS code")
        temp_file = f.name
    
    try:
        result = scanner.scan_file(temp_file)
        assert result.is_malicious is True
        assert len(result.matches) > 0
    finally:
        Path(temp_file).unlink()


def test_scan_file_clean(scanner):
    """Test scanning a clean file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("This is safe content")
        temp_file = f.name
    
    try:
        result = scanner.scan_file(temp_file)
        assert result.is_malicious is False
        assert len(result.matches) == 0
    finally:
        Path(temp_file).unlink()


def test_scan_nonexistent_file(scanner):
    """Test scanning a non-existent file."""
    result = scanner.scan_file("/nonexistent/file.txt")
    assert result.error is not None
    assert "not found" in result.error.lower() or "no such file" in result.error.lower()


def test_scan_result_serialization(scanner):
    """Test ScanResult serialization."""
    data = b"MALICIOUS content"
    result = scanner.scan_data(data, "test")
    
    # Test to_dict
    result_dict = result.to_dict()
    assert isinstance(result_dict, dict)
    assert 'file_path' in result_dict
    assert 'is_malicious' in result_dict
    assert 'matches' in result_dict
    
    # Test to_json
    result_json = result.to_json()
    assert isinstance(result_json, str)
    assert "test" in result_json


def test_yara_match_structure(scanner):
    """Test YaraMatch data structure."""
    data = b"MALICIOUS content"
    result = scanner.scan_data(data, "test")
    
    assert len(result.matches) > 0
    match = result.matches[0]
    
    assert isinstance(match, YaraMatch)
    assert match.rule_name == "TestRule"
    assert isinstance(match.tags, list)
    assert isinstance(match.metadata, dict)
    assert 'description' in match.metadata


def test_scan_directory(scanner):
    """Test scanning a directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test files
        (temp_path / "malicious.txt").write_text("MALICIOUS")
        (temp_path / "clean.txt").write_text("harmless")
        (temp_path / "safe.txt").write_text("SAFE")
        
        results = scanner.scan_directory(temp_path)
        
        assert len(results) == 3
        malicious_count = sum(1 for r in results if r.is_malicious)
        assert malicious_count > 0


def test_multiple_matches(scanner):
    """Test file with multiple rule matches."""
    data = b"This has both MALICIOUS and SAFE patterns"
    result = scanner.scan_data(data, "test")
    
    # Should match both rules
    assert result.is_malicious is True
    assert len(result.matches) >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
