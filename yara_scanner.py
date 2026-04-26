"""
Yara-X Scanner Module for Sanitizer Engine
Provides malware detection and file scanning capabilities using Yara-X rules.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    import yara_x
except ImportError:
    raise ImportError(
        "yara-x is not installed. Install it with: pip install yara-x"
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class YaraMatch:
    """Represents a single Yara rule match."""
    rule_name: str
    namespace: str
    tags: List[str]
    metadata: Dict[str, any]
    strings: List[Dict[str, any]]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ScanResult:
    """Represents the result of scanning a file."""
    file_path: str
    file_size: int
    scan_time: float
    timestamp: str
    matches: List[YaraMatch]
    is_malicious: bool
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        result = asdict(self)
        result['matches'] = [match.to_dict() for match in self.matches]
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class YaraXScanner:
    """
    Yara-X based file scanner for malware detection.
    
    This scanner compiles Yara rules and scans files for potential threats.
    """
    
    def __init__(self, rules_path: Union[str, Path], namespace: str = "default"):
        """
        Initialize the Yara-X scanner.
        
        Args:
            rules_path: Path to Yara rules file or directory
            namespace: Namespace for the rules (default: "default")
        """
        self.rules_path = Path(rules_path)
        self.namespace = namespace
        self.scanner = None
        self._load_rules()
    
    def _load_rules(self):
        """Load and compile Yara rules."""
        try:
            logger.info(f"Loading Yara rules from: {self.rules_path}")
            
            if not self.rules_path.exists():
                raise FileNotFoundError(f"Rules path not found: {self.rules_path}")
            
            # Create a compiler
            compiler = yara_x.Compiler()
            
            # Add rules from file or directory
            if self.rules_path.is_file():
                self._add_rule_file(compiler, self.rules_path)
            elif self.rules_path.is_dir():
                self._add_rules_from_directory(compiler, self.rules_path)
            else:
                raise ValueError(f"Invalid rules path: {self.rules_path}")
            
            # Build the scanner
            rules = compiler.build()
            self.scanner = yara_x.Scanner(rules)
            
            logger.info("Yara rules loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load Yara rules: {e}")
            raise
    
    def _add_rule_file(self, compiler: yara_x.Compiler, file_path: Path):
        """Add a single rule file to the compiler."""
        try:
            with open(file_path, 'r') as f:
                rule_content = f.read()
            compiler.new_namespace(self.namespace)
            compiler.add_source(rule_content)
            logger.debug(f"Added rule file: {file_path}")
        except Exception as e:
            logger.warning(f"Failed to add rule file {file_path}: {e}")
    
    def _add_rules_from_directory(self, compiler: yara_x.Compiler, dir_path: Path):
        """Add all .yar and .yara files from a directory."""
        rule_files = list(dir_path.glob("**/*.yar")) + list(dir_path.glob("**/*.yara"))
        
        if not rule_files:
            logger.warning(f"No Yara rule files found in: {dir_path}")
            return
        
        for rule_file in rule_files:
            self._add_rule_file(compiler, rule_file)
    
    def scan_file(self, file_path: Union[str, Path], timeout: int = 60) -> ScanResult:
        """
        Scan a single file with Yara rules.
        
        Args:
            file_path: Path to the file to scan
            timeout: Scan timeout in seconds (default: 60)
            
        Returns:
            ScanResult object containing match information
        """
        file_path = Path(file_path)
        start_time = datetime.now()
        
        try:
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            if not file_path.is_file():
                raise ValueError(f"Not a file: {file_path}")
            
            file_size = file_path.stat().st_size
            logger.info(f"Scanning file: {file_path} ({file_size} bytes)")
            
            # Set timeout
            self.scanner.set_timeout(timeout)
            
            # Scan the file
            matches = self.scanner.scan_file(str(file_path))
            
            # Parse matches
            yara_matches = self._parse_matches(matches)
            
            # Calculate scan time
            scan_time = (datetime.now() - start_time).total_seconds()
            
            # Create result
            result = ScanResult(
                file_path=str(file_path),
                file_size=file_size,
                scan_time=scan_time,
                timestamp=datetime.now().isoformat(),
                matches=yara_matches,
                is_malicious=len(yara_matches) > 0
            )
            
            if result.is_malicious:
                logger.warning(f"Malicious file detected: {file_path} - {len(yara_matches)} matches")
            else:
                logger.info(f"File clean: {file_path}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            scan_time = (datetime.now() - start_time).total_seconds()
            
            return ScanResult(
                file_path=str(file_path),
                file_size=0,
                scan_time=scan_time,
                timestamp=datetime.now().isoformat(),
                matches=[],
                is_malicious=False,
                error=str(e)
            )
    
    def scan_data(self, data: bytes, identifier: str = "memory") -> ScanResult:
        """
        Scan data in memory with Yara rules.
        
        Args:
            data: Bytes to scan
            identifier: Identifier for the data being scanned
            
        Returns:
            ScanResult object containing match information
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"Scanning data: {identifier} ({len(data)} bytes)")
            
            # Scan the data
            matches = self.scanner.scan(data)
            
            # Parse matches
            yara_matches = self._parse_matches(matches)
            
            # Calculate scan time
            scan_time = (datetime.now() - start_time).total_seconds()
            
            # Create result
            result = ScanResult(
                file_path=identifier,
                file_size=len(data),
                scan_time=scan_time,
                timestamp=datetime.now().isoformat(),
                matches=yara_matches,
                is_malicious=len(yara_matches) > 0
            )
            
            if result.is_malicious:
                logger.warning(f"Malicious data detected: {identifier} - {len(yara_matches)} matches")
            else:
                logger.info(f"Data clean: {identifier}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error scanning data {identifier}: {e}")
            scan_time = (datetime.now() - start_time).total_seconds()
            
            return ScanResult(
                file_path=identifier,
                file_size=len(data),
                scan_time=scan_time,
                timestamp=datetime.now().isoformat(),
                matches=[],
                is_malicious=False,
                error=str(e)
            )
    
    def _parse_matches(self, matches) -> List[YaraMatch]:
        """Parse Yara-X match results into YaraMatch objects."""
        yara_matches = []
        
        for match in matches:
            # Extract string matches
            strings = []
            for pattern in match.patterns:
                for m in pattern.matches:
                    strings.append({
                        'identifier': pattern.identifier,
                        'offset': m.offset,
                        'length': m.length,
                        'data': m.data.decode('utf-8', errors='replace') if isinstance(m.data, bytes) else str(m.data)
                    })
            
            # Create YaraMatch object
            yara_match = YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace,
                tags=list(match.tags),
                metadata=dict(match.metadata),
                strings=strings
            )
            yara_matches.append(yara_match)
        
        return yara_matches
    
    def scan_directory(self, 
                      dir_path: Union[str, Path], 
                      recursive: bool = True,
                      extensions: Optional[List[str]] = None) -> List[ScanResult]:
        """
        Scan all files in a directory.
        
        Args:
            dir_path: Path to directory to scan
            recursive: Whether to scan subdirectories (default: True)
            extensions: List of file extensions to scan (e.g., ['.exe', '.dll'])
                       If None, scans all files
            
        Returns:
            List of ScanResult objects
        """
        dir_path = Path(dir_path)
        results = []
        
        if not dir_path.exists() or not dir_path.is_dir():
            logger.error(f"Invalid directory: {dir_path}")
            return results
        
        # Get files to scan
        if recursive:
            files = dir_path.rglob("*")
        else:
            files = dir_path.glob("*")
        
        # Filter by extension if specified
        if extensions:
            files = [f for f in files if f.suffix.lower() in [ext.lower() for ext in extensions]]
        else:
            files = [f for f in files if f.is_file()]
        
        logger.info(f"Scanning {len(files)} files in {dir_path}")
        
        for file_path in files:
            if file_path.is_file():
                result = self.scan_file(file_path)
                results.append(result)
        
        # Summary
        malicious_count = sum(1 for r in results if r.is_malicious)
        logger.info(f"Scan complete: {len(results)} files scanned, {malicious_count} threats detected")
        
        return results
    
    def reload_rules(self):
        """Reload Yara rules from the original path."""
        logger.info("Reloading Yara rules")
        self._load_rules()


def main():
    """Example usage of YaraXScanner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Yara-X File Scanner")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("-r", "--rules", required=True, help="Path to Yara rules file/directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    parser.add_argument("--recursive", action="store_true", help="Scan directories recursively")
    parser.add_argument("--timeout", type=int, default=60, help="Scan timeout in seconds")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = YaraXScanner(args.rules)
    
    target_path = Path(args.target)
    
    # Scan
    if target_path.is_file():
        result = scanner.scan_file(target_path, timeout=args.timeout)
        results = [result]
    elif target_path.is_dir():
        results = scanner.scan_directory(target_path, recursive=args.recursive)
    else:
        print(f"Error: Invalid target path: {target_path}")
        return
    
    # Display results
    for result in results:
        print(f"\n{'='*60}")
        print(f"File: {result.file_path}")
        print(f"Status: {'MALICIOUS' if result.is_malicious else 'CLEAN'}")
        print(f"Scan Time: {result.scan_time:.2f}s")
        
        if result.matches:
            print(f"\nMatches ({len(result.matches)}):")
            for match in result.matches:
                print(f"  - {match.rule_name} [{', '.join(match.tags)}]")
                if match.metadata:
                    print(f"    Metadata: {match.metadata}")
    
    # Save to JSON if requested
    if args.output:
        output_data = {
            'scan_summary': {
                'total_files': len(results),
                'malicious_files': sum(1 for r in results if r.is_malicious),
                'scan_date': datetime.now().isoformat()
            },
            'results': [r.to_dict() for r in results]
        }
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
