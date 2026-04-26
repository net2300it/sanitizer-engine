"""
Sanitizer Engine Integration for Yara-X Scanner
Provides seamless integration between the sanitizer engine and Yara-X scanning.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union, Callable
from enum import Enum
from dataclasses import dataclass

from yara_scanner import YaraXScanner, ScanResult

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanAction(Enum):
    """Actions to take on malicious files."""
    QUARANTINE = "quarantine"
    DELETE = "delete"
    BLOCK = "block"
    LOG = "log"
    NOTIFY = "notify"


@dataclass
class SanitizerConfig:
    """Configuration for the sanitizer with Yara-X integration."""
    rules_path: str
    quarantine_dir: str = "/tmp/quarantine"
    enable_auto_quarantine: bool = True
    enable_logging: bool = True
    scan_timeout: int = 60
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    excluded_extensions: List[str] = None
    threat_actions: Dict[ThreatLevel, List[ScanAction]] = None
    
    def __post_init__(self):
        if self.excluded_extensions is None:
            self.excluded_extensions = []
        
        if self.threat_actions is None:
            self.threat_actions = {
                ThreatLevel.CRITICAL: [ScanAction.QUARANTINE, ScanAction.LOG, ScanAction.NOTIFY],
                ThreatLevel.HIGH: [ScanAction.QUARANTINE, ScanAction.LOG],
                ThreatLevel.MEDIUM: [ScanAction.LOG, ScanAction.NOTIFY],
                ThreatLevel.LOW: [ScanAction.LOG],
                ThreatLevel.INFO: [ScanAction.LOG]
            }


class SanitizerYaraIntegration:
    """
    Integration layer between sanitizer engine and Yara-X scanner.
    
    Provides file sanitization, threat detection, and automated response.
    """
    
    def __init__(self, config: SanitizerConfig):
        """
        Initialize the sanitizer integration.
        
        Args:
            config: SanitizerConfig object with settings
        """
        self.config = config
        self.scanner = YaraXScanner(config.rules_path)
        self.quarantine_dir = Path(config.quarantine_dir)
        
        # Create quarantine directory if needed
        if config.enable_auto_quarantine:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'files_blocked': 0,
            'scan_errors': 0
        }
        
        logger.info("Sanitizer Yara-X integration initialized")
    
    def sanitize_file(self, file_path: Union[str, Path]) -> Dict:
        """
        Scan and sanitize a file.
        
        Args:
            file_path: Path to file to sanitize
            
        Returns:
            Dictionary with sanitization result
        """
        file_path = Path(file_path)
        
        try:
            # Check if file exists
            if not file_path.exists():
                return self._create_result(False, "File not found", file_path)
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.config.max_file_size:
                return self._create_result(
                    False, 
                    f"File too large ({file_size} bytes, max: {self.config.max_file_size})",
                    file_path
                )
            
            # Check excluded extensions
            if file_path.suffix.lower() in self.config.excluded_extensions:
                return self._create_result(
                    True,
                    "File extension excluded from scanning",
                    file_path,
                    skipped=True
                )
            
            # Scan the file
            scan_result = self.scanner.scan_file(file_path, timeout=self.config.scan_timeout)
            self.stats['files_scanned'] += 1
            
            if scan_result.error:
                self.stats['scan_errors'] += 1
                return self._create_result(False, f"Scan error: {scan_result.error}", file_path)
            
            # Process results
            if scan_result.is_malicious:
                self.stats['threats_detected'] += 1
                return self._handle_threat(file_path, scan_result)
            else:
                return self._create_result(True, "File is clean", file_path, scan_result=scan_result)
        
        except Exception as e:
            logger.error(f"Error sanitizing file {file_path}: {e}")
            self.stats['scan_errors'] += 1
            return self._create_result(False, f"Exception: {str(e)}", file_path)
    
    def _handle_threat(self, file_path: Path, scan_result: ScanResult) -> Dict:
        """Handle a detected threat based on configuration."""
        # Determine threat level
        threat_level = self._assess_threat_level(scan_result)
        
        # Get configured actions
        actions = self.config.threat_actions.get(threat_level, [ScanAction.LOG])
        
        # Execute actions
        action_results = {}
        
        if ScanAction.QUARANTINE in actions and self.config.enable_auto_quarantine:
            quarantine_result = self._quarantine_file(file_path)
            action_results['quarantine'] = quarantine_result
            if quarantine_result:
                self.stats['files_quarantined'] += 1
        
        if ScanAction.DELETE in actions:
            delete_result = self._delete_file(file_path)
            action_results['delete'] = delete_result
        
        if ScanAction.BLOCK in actions:
            # Block would be handled by the caller
            self.stats['files_blocked'] += 1
            action_results['block'] = True
        
        if ScanAction.LOG in actions and self.config.enable_logging:
            self._log_threat(file_path, scan_result, threat_level)
            action_results['log'] = True
        
        if ScanAction.NOTIFY in actions:
            # Notification would be handled by callback
            action_results['notify'] = True
        
        return self._create_result(
            False,
            f"Threat detected: {threat_level.value}",
            file_path,
            scan_result=scan_result,
            threat_level=threat_level.value,
            actions_taken=action_results
        )
    
    def _assess_threat_level(self, scan_result: ScanResult) -> ThreatLevel:
        """Assess threat level based on matches."""
        if not scan_result.matches:
            return ThreatLevel.INFO
        
        # Check for critical indicators
        for match in scan_result.matches:
            tags = [tag.lower() for tag in match.tags]
            metadata = {k.lower(): v for k, v in match.metadata.items()}
            
            # Critical threats
            if any(tag in tags for tag in ['ransomware', 'trojan', 'backdoor', 'rootkit']):
                return ThreatLevel.CRITICAL
            
            if metadata.get('severity') == 'critical':
                return ThreatLevel.CRITICAL
            
            # High threats
            if any(tag in tags for tag in ['malware', 'exploit', 'virus', 'worm']):
                return ThreatLevel.HIGH
            
            if metadata.get('severity') == 'high':
                return ThreatLevel.HIGH
        
        # Default based on number of matches
        if len(scan_result.matches) >= 3:
            return ThreatLevel.HIGH
        elif len(scan_result.matches) >= 2:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _quarantine_file(self, file_path: Path) -> bool:
        """Move file to quarantine directory."""
        try:
            import shutil
            from datetime import datetime
            
            # Create unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{file_path.name}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Move file
            shutil.move(str(file_path), str(quarantine_path))
            
            # Create metadata file
            metadata_path = quarantine_path.with_suffix(quarantine_path.suffix + '.meta')
            with open(metadata_path, 'w') as f:
                f.write(f"Original path: {file_path}\n")
                f.write(f"Quarantined at: {datetime.now().isoformat()}\n")
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
    
    def _delete_file(self, file_path: Path) -> bool:
        """Securely delete a file."""
        try:
            file_path.unlink()
            logger.info(f"File deleted: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete file {file_path}: {e}")
            return False
    
    def _log_threat(self, file_path: Path, scan_result: ScanResult, threat_level: ThreatLevel):
        """Log threat detection."""
        logger.warning(
            f"THREAT DETECTED - Level: {threat_level.value} | "
            f"File: {file_path} | "
            f"Matches: {len(scan_result.matches)} | "
            f"Rules: {', '.join(m.rule_name for m in scan_result.matches)}"
        )
    
    def _create_result(self, 
                      safe: bool, 
                      message: str, 
                      file_path: Path,
                      scan_result: Optional[ScanResult] = None,
                      skipped: bool = False,
                      **kwargs) -> Dict:
        """Create a standardized result dictionary."""
        result = {
            'safe': safe,
            'skipped': skipped,
            'message': message,
            'file_path': str(file_path),
            **kwargs
        }
        
        if scan_result:
            result['scan_details'] = {
                'matches': len(scan_result.matches),
                'scan_time': scan_result.scan_time,
                'file_size': scan_result.file_size,
                'rules_matched': [m.rule_name for m in scan_result.matches]
            }
        
        return result
    
    def scan_upload(self, file_data: bytes, filename: str) -> Dict:
        """
        Scan uploaded file data before saving.
        
        Args:
            file_data: File contents as bytes
            filename: Original filename
            
        Returns:
            Dictionary with scan result
        """
        try:
            # Scan data in memory
            scan_result = self.scanner.scan_data(file_data, identifier=filename)
            self.stats['files_scanned'] += 1
            
            if scan_result.error:
                self.stats['scan_errors'] += 1
                return self._create_result(False, f"Scan error: {scan_result.error}", Path(filename))
            
            if scan_result.is_malicious:
                self.stats['threats_detected'] += 1
                threat_level = self._assess_threat_level(scan_result)
                
                return {
                    'safe': False,
                    'message': f"Threat detected in upload: {threat_level.value}",
                    'filename': filename,
                    'threat_level': threat_level.value,
                    'scan_details': {
                        'matches': len(scan_result.matches),
                        'rules_matched': [m.rule_name for m in scan_result.matches]
                    }
                }
            else:
                return {
                    'safe': True,
                    'message': "Upload is clean",
                    'filename': filename
                }
        
        except Exception as e:
            logger.error(f"Error scanning upload {filename}: {e}")
            self.stats['scan_errors'] += 1
            return self._create_result(False, f"Exception: {str(e)}", Path(filename))
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics."""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset all statistics."""
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'files_blocked': 0,
            'scan_errors': 0
        }
