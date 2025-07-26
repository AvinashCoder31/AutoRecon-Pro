"""
AutoRecon-Pro Pattern Matcher Module
AI-powered pattern recognition for vulnerability and credential detection
"""

import re
import json
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)

class PatternMatcher:
    """
    Advanced pattern matching engine for security analysis
    """
    
    def __init__(self):
        """
        Initialize the pattern matcher with predefined patterns
        """
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.credential_patterns = self._load_credential_patterns()
        self.service_patterns = self._load_service_patterns()
        self.custom_patterns = {}
        
    def _load_vulnerability_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Load vulnerability detection patterns
        
        Returns:
            Dict[str, Dict[str, Any]]: Vulnerability patterns
        """
        return {
            'sql_injection': {
                'patterns': [
                    r'SQL syntax.*?error',
                    r'mysql_fetch_array\(\)',
                    r'ORA-\d{5}',
                    r'Microsoft OLE DB Provider for ODBC Drivers',
                    r'PostgreSQL.*?ERROR',
                    r'Warning.*?mysql_.*',
                    r'valid MySQL result',
                    r'MySqlClient\.',
                ],
                'severity': 'critical',
                'category': 'injection',
                'description': 'Potential SQL injection vulnerability detected'
            },
            'xss': {
                'patterns': [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'eval\s*\(',
                    r'document\.write',
                    r'innerHTML\s*=',
                ],
                'severity': 'high',
                'category': 'injection',
                'description': 'Potential Cross-Site Scripting (XSS) vulnerability detected'
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./\.\./\.\.',
                    r'\.\.\\\.\.\\\.\.\\',
                    r'%2e%2e%2f',
                    r'%2e%2e%5c',
                    r'\.\.%2f',
                    r'\.\.%5c',
                ],
                'severity': 'high',
                'category': 'path_traversal',
                'description': 'Potential path traversal vulnerability detected'
            },
            'command_injection': {
                'patterns': [
                    r';\s*(?:cat|ls|pwd|id|whoami|uname)',
                    r'\|\s*(?:cat|ls|pwd|id|whoami|uname)',
                    r'`.*?`',
                    r'\$\(.*?\)',
                    r'&&\s*(?:cat|ls|pwd|id|whoami|uname)',
                ],
                'severity': 'critical',
                'category': 'injection',
                'description': 'Potential command injection vulnerability detected'
            },
            'ldap_injection': {
                'patterns': [
                    r'\*\)\(\|\(',
                    r'\*\)\(\&\(',
                    r'\*\)\(\!\(',
                    r'\)\(\|\(',
                    r'\)\(\&\(',
                ],
                'severity': 'high',
                'category': 'injection',
                'description': 'Potential LDAP injection vulnerability detected'
            },
            'xml_injection': {
                'patterns': [
                    r'<!ENTITY.*?>',
                    r'<!DOCTYPE.*?\[',
                    r'&\w+;',
                    r'<!\[CDATA\[',
                ],
                'severity': 'medium',
                'category': 'injection',
                'description': 'Potential XML injection vulnerability detected'
            },
            'information_disclosure': {
                'patterns': [
                    r'MySQL.*?at line \d+',
                    r'Fatal error.*?in.*?on line \d+',
                    r'Warning.*?in.*?on line \d+',
                    r'Microsoft OLE DB.*?error',
                    r'Stack trace:',
                    r'Exception.*?at.*?line \d+',
                ],
                'severity': 'medium',
                'category': 'information_disclosure',
                'description': 'Information disclosure through error messages'
            },
            'weak_crypto': {
                'patterns': [
                    r'MD5\s*\(',
                    r'SHA1\s*\(',
                    r'DES\s*\(',
                    r'RC4\s*\(',
                    r'ssl.*?v[23]',
                ],
                'severity': 'medium',
                'category': 'cryptography',
                'description': 'Weak cryptographic algorithm detected'
            }
        }
    
    def _load_credential_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Load credential detection patterns
        
        Returns:
            Dict[str, Dict[str, Any]]: Credential patterns
        """
        return {
            'password': {
                'patterns': [
                    r'password\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
                    r'passwd\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
                    r'pwd\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
                    r'pass\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
                ],
                'severity': 'high',
                'category': 'credentials',
                'description': 'Hardcoded password detected'
            },
            'api_key': {
                'patterns': [
                    r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',
                    r'apikey\s*[=:]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',
                    r'api[_-]?secret\s*[=:]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',
                    r'client[_-]?secret\s*[=:]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',
                ],
                'severity': 'critical',
                'category': 'credentials',
                'description': 'API key or secret detected'
            },
            'database_connection': {
                'patterns': [
                    r'mysql://([^:\s]+):([^@\s]+)@([^:/\s]+)',
                    r'postgresql://([^:\s]+):([^@\s]+)@([^:/\s]+)',
                    r'mongodb://([^:\s]+):([^@\s]+)@([^:/\s]+)',
                    r'jdbc:mysql://([^:\s]+):([^@\s]+)@([^:/\s]+)',
                ],
                'severity': 'high',
                'category': 'credentials',
                'description': 'Database connection string with credentials detected'
            },
            'private_key': {
                'patterns': [
                    r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
                    r'-----BEGIN OPENSSH PRIVATE KEY-----',
                    r'-----BEGIN DSA PRIVATE KEY-----',
                    r'-----BEGIN EC PRIVATE KEY-----',
                ],
                'severity': 'critical',
                'category': 'credentials',
                'description': 'Private key detected'
            },
            'jwt_token': {
                'patterns': [
                    r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                ],
                'severity': 'high',
                'category': 'credentials',
                'description': 'JWT token detected'
            },
            'aws_credentials': {
                'patterns': [
                    r'AKIA[0-9A-Z]{16}',
                    r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?',
                    r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
                ],
                'severity': 'critical',
                'category': 'credentials',
                'description': 'AWS credentials detected'
            },
            'github_token': {
                'patterns': [
                    r'ghp_[a-zA-Z0-9]{36}',
                    r'gho_[a-zA-Z0-9]{36}',
                    r'ghu_[a-zA-Z0-9]{36}',
                    r'ghs_[a-zA-Z0-9]{36}',
                    r'ghr_[a-zA-Z0-9]{36}',
                ],
                'severity': 'critical',
                'category': 'credentials',
                'description': 'GitHub token detected'
            },
            'email_credentials': {
                'patterns': [
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[a-zA-Z0-9!@#$%^&*()_+-=]{6,}',
                ],
                'severity': 'medium',
                'category': 'credentials',
                'description': 'Email credentials detected'
            }
        }
    
    def _load_service_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Load service detection patterns
        
        Returns:
            Dict[str, Dict[str, Any]]: Service patterns
        """
        return {
            'web_servers': {
                'patterns': [
                    r'Apache/(\d+\.\d+\.\d+)',
                    r'nginx/(\d+\.\d+\.\d+)',
                    r'Microsoft-IIS/(\d+\.\d+)',
                    r'lighttpd/(\d+\.\d+\.\d+)',
                    r'Cherokee/(\d+\.\d+\.\d+)',
                ],
                'category': 'web_server',
                'description': 'Web server version detected'
            },
            'databases': {
                'patterns': [
                    r'MySQL (\d+\.\d+\.\d+)',
                    r'PostgreSQL (\d+\.\d+)',
                    r'Microsoft SQL Server (\d+\.\d+)',
                    r'Oracle Database (\d+\.\d+)',
                    r'MongoDB (\d+\.\d+\.\d+)',
                ],
                'category': 'database',
                'description': 'Database server version detected'
            },
            'programming_languages': {
                'patterns': [
                    r'PHP/(\d+\.\d+\.\d+)',
                    r'Python/(\d+\.\d+\.\d+)',
                    r'Java/(\d+\.\d+\.\d+)',
                    r'Node\.js/(\d+\.\d+\.\d+)',
                    r'Ruby (\d+\.\d+\.\d+)',
                ],
                'category': 'programming_language',
                'description': 'Programming language version detected'
            },
            'cms_frameworks': {
                'patterns': [
                    r'WordPress (\d+\.\d+)',
                    r'Drupal (\d+\.\d+)',
                    r'Joomla! (\d+\.\d+)',
                    r'Django/(\d+\.\d+)',
                    r'Laravel (\d+\.\d+)',
                ],
                'category': 'cms_framework',
                'description': 'CMS or framework version detected'
            },
            'operating_systems': {
                'patterns': [
                    r'Linux.*?(\d+\.\d+\.\d+)',
                    r'Windows.*?(\d+\.\d+)',
                    r'Ubuntu (\d+\.\d+)',
                    r'CentOS (\d+\.\d+)',
                    r'FreeBSD (\d+\.\d+)',
                ],
                'category': 'operating_system',
                'description': 'Operating system version detected'
            }
        }
    
    def analyze_text(self, text: str, target: str = "unknown") -> Dict[str, List[Dict[str, Any]]]:
        """
        Analyze text for vulnerabilities, credentials, and services
        
        Args:
            text (str): Text to analyze
            target (str): Target identifier
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Analysis results
        """
        results = {
            'vulnerabilities': [],
            'credentials': [],
            'services': [],
            'custom_matches': []
        }
        
        # Analyze vulnerabilities
        results['vulnerabilities'] = self._match_patterns(
            text, self.vulnerability_patterns, target
        )
        
        # Analyze credentials
        results['credentials'] = self._match_patterns(
            text, self.credential_patterns, target
        )
        
        # Analyze services
        results['services'] = self._match_patterns(
            text, self.service_patterns, target
        )
        
        # Analyze custom patterns
        if self.custom_patterns:
            results['custom_matches'] = self._match_patterns(
                text, self.custom_patterns, target
            )
        
        logger.debug(f"Pattern analysis completed for {target}")
        return results
    
    def _match_patterns(self, text: str, patterns: Dict[str, Dict[str, Any]], 
                       target: str) -> List[Dict[str, Any]]:
        """
        Match text against pattern dictionary
        
        Args:
            text (str): Text to analyze
            patterns (Dict): Pattern dictionary
            target (str): Target identifier
            
        Returns:
            List[Dict[str, Any]]: Matched patterns
        """
        matches = []
        
        for pattern_name, pattern_info in patterns.items():
            for pattern in pattern_info['patterns']:
                compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                pattern_matches = compiled_pattern.finditer(text)
                
                for match in pattern_matches:
                    match_data = {
                        'name': pattern_name,
                        'pattern': pattern,
                        'match': match.group(0),
                        'start': match.start(),
                        'end': match.end(),
                        'target': target,
                        'severity': pattern_info.get('severity', 'info'),
                        'category': pattern_info.get('category', 'unknown'),
                        'description': pattern_info['description'],
                        'confidence': self._calculate_confidence(match.group(0), pattern),
                        'context': self._extract_context(text, match.start(), match.end())
                    }
                    
                    # Extract captured groups if present
                    if match.groups():
                        match_data['captured_groups'] = match.groups()
                    
                    matches.append(match_data)
        
        return matches
    
    def _calculate_confidence(self, match: str, pattern: str) -> float:
        """
        Calculate confidence score for a pattern match
        
        Args:
            match (str): Matched text
            pattern (str): Pattern used
            
        Returns:
            float: Confidence score (0.0 - 1.0)
        """
        # Base confidence
        confidence = 0.7
        
        # Increase confidence for longer matches
        if len(match) > 20:
            confidence += 0.1
        
        # Increase confidence for specific patterns
        if any(keyword in pattern.lower() for keyword in ['password', 'key', 'secret']):
            confidence += 0.2
        
        # Decrease confidence for common false positives
        if any(fp in match.lower() for fp in ['example', 'test', 'demo', 'placeholder']):
            confidence -= 0.3
        
        return max(0.0, min(1.0, confidence))
    
    def _extract_context(self, text: str, start: int, end: int, 
                        context_size: int = 100) -> str:
        """
        Extract context around a match
        
        Args:
            text (str): Full text
            start (int): Match start position
            end (int): Match end position
            context_size (int): Context size in characters
            
        Returns:
            str: Context around the match
        """
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        
        context = text[context_start:context_end]
        
        # Add ellipsis if truncated
        if context_start > 0:
            context = "..." + context
        if context_end < len(text):
            context = context + "..."
        
        return context
    
    def add_custom_pattern(self, name: str, patterns: List[str], 
                          severity: str = "info", category: str = "custom",
                          description: str = "Custom pattern match") -> None:
        """
        Add custom pattern for detection
        
        Args:
            name (str): Pattern name
            patterns (List[str]): List of regex patterns
            severity (str): Severity level
            category (str): Pattern category
            description (str): Pattern description
        """
        self.custom_patterns[name] = {
            'patterns': patterns,
            'severity': severity,
            'category': category,
            'description': description
        }
        
        logger.info(f"Added custom pattern: {name}")
    
    def remove_custom_pattern(self, name: str) -> bool:
        """
        Remove custom pattern
        
        Args:
            name (str): Pattern name to remove
            
        Returns:
            bool: True if removed, False if not found
        """
        if name in self.custom_patterns:
            del self.custom_patterns[name]
            logger.info(f"Removed custom pattern: {name}")
            return True
        return False
    
    def analyze_file(self, file_path: str, target: str = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Analyze file content for patterns
        
        Args:
            file_path (str): Path to file
            target (str, optional): Target identifier
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Analysis results
        """
        try:
            file_path = Path(file_path)
            if not target:
                target = file_path.name
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            results = self.analyze_text(content, target)
            results['file_info'] = {
                'path': str(file_path),
                'size': file_path.stat().st_size,
                'hash': hashlib.md5(content.encode()).hexdigest()
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {'error': str(e)}
    
    def analyze_directory(self, directory_path: str, 
                         file_extensions: List[str] = None) -> Dict[str, Any]:
        """
        Analyze all files in a directory
        
        Args:
            directory_path (str): Path to directory
            file_extensions (List[str], optional): File extensions to analyze
            
        Returns:
            Dict[str, Any]: Combined analysis results
        """
        if not file_extensions:
            file_extensions = ['.txt', '.log', '.conf', '.config', '.ini', '.xml', 
                             '.json', '.yaml', '.yml', '.php', '.py', '.js', '.html']
        
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            return {'error': f"Directory {directory_path} not found"}
        
        combined_results = {
            'vulnerabilities': [],
            'credentials': [],
            'services': [],
            'custom_matches': [],
            'file_count': 0,
            'analyzed_files': []
        }
        
        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in file_extensions:
                try:
                    results = self.analyze_file(file_path, str(file_path.relative_to(directory)))
                    
                    if 'error' not in results:
                        combined_results['vulnerabilities'].extend(results.get('vulnerabilities', []))
                        combined_results['credentials'].extend(results.get('credentials', []))
                        combined_results['services'].extend(results.get('services', []))
                        combined_results['custom_matches'].extend(results.get('custom_matches', []))
                        combined_results['analyzed_files'].append(str(file_path))
                        combined_results['file_count'] += 1
                        
                except Exception as e:
                    logger.warning(f"Skipping file {file_path}: {str(e)}")
        
        return combined_results
    
    def generate_risk_score(self, analysis_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Generate risk score based on analysis results
        
        Args:
            analysis_results (Dict): Analysis results
            
        Returns:
            Dict[str, Any]: Risk assessment
        """
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
        
        total_score = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # Calculate score for each category
        for category in ['vulnerabilities', 'credentials', 'services', 'custom_matches']:
            items = analysis_results.get(category, [])
            for item in items:
                severity = item.get('severity', 'info').lower()
                if severity in severity_weights:
                    total_score += severity_weights[severity]
                    severity_counts[severity] += 1
        
        # Normalize score (0-100)
        max_possible_score = len(analysis_results.get('vulnerabilities', [])) * 10
        normalized_score = min(100, (total_score / max(max_possible_score, 1)) * 100) if max_possible_score > 0 else 0
        
        # Determine risk level
        if normalized_score >= 80:
            risk_level = 'CRITICAL'
        elif normalized_score >= 60:
            risk_level = 'HIGH'
        elif normalized_score >= 40:
            risk_level = 'MEDIUM'
        elif normalized_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'total_score': total_score,
            'normalized_score': round(normalized_score, 2),
            'risk_level': risk_level,
            'severity_counts': severity_counts,
            'total_findings': sum(severity_counts.values()),
            'recommendations': self._generate_recommendations(severity_counts)
        }
    
    def _generate_recommendations(self, severity_counts: Dict[str, int]) -> List[str]:
        """
        Generate security recommendations based on findings
        
        Args:
            severity_counts (Dict[str, int]): Severity count dictionary
            
        Returns:
            List[str]: List of recommendations
        """
        recommendations = []
        
        if severity_counts['critical'] > 0:
            recommendations.append("Immediately address critical vulnerabilities and exposed credentials")
            recommendations.append("Conduct emergency security review and incident response")
        
        if severity_counts['high'] > 0:
            recommendations.append("Prioritize remediation of high-severity findings")
            recommendations.append("Implement additional security controls and monitoring")
        
        if severity_counts['medium'] > 0:
            recommendations.append("Schedule remediation of medium-severity issues")
            recommendations.append("Review security configurations and best practices")
        
        if severity_counts['low'] > 0:
            recommendations.append("Address low-severity findings during regular maintenance")
        
        if sum(severity_counts.values()) > 10:
            recommendations.append("Consider comprehensive security audit and assessment")
        
        # Generic recommendations
        recommendations.extend([
            "Implement regular security scanning and monitoring",
            "Establish secure coding practices and code review processes",
            "Maintain up-to-date security patches and configurations",
            "Provide security training for development and operations teams"
        ])
        
        return recommendations
    
    def export_patterns(self, file_path: str) -> bool:
        """
        Export all patterns to JSON file
        
        Args:
            file_path (str): Export file path
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            patterns_data = {
                'vulnerability_patterns': self.vulnerability_patterns,
                'credential_patterns': self.credential_patterns,
                'service_patterns': self.service_patterns,
                'custom_patterns': self.custom_patterns,
                'exported_at': datetime.datetime.now().isoformat()
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(patterns_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Patterns exported to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting patterns: {str(e)}")
            return False
    
    def import_patterns(self, file_path: str) -> bool:
        """
        Import patterns from JSON file
        
        Args:
            file_path (str): Import file path
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                patterns_data = json.load(f)
            
            if 'custom_patterns' in patterns_data:
                self.custom_patterns.update(patterns_data['custom_patterns'])
            
            logger.info(f"Patterns imported from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error importing patterns: {str(e)}")
            return False