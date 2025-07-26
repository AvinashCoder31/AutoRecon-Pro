"""
AutoRecon-Pro Report Generator Module
Generates comprehensive reports in multiple formats (HTML, JSON, XML, PDF, TXT)
"""

import json
import xml.etree.ElementTree as ET
import os
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Advanced report generator with multiple format support
    """
    
    def __init__(self, output_dir: str = "results"):
        """
        Initialize the report generator
        
        Args:
            output_dir (str): Output directory for reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_results = {}
        self.scan_metadata = {}
        
    def add_scan_result(self, target: str, plugin: str, result: Dict[str, Any]) -> None:
        """
        Add scan result for a target and plugin
        
        Args:
            target (str): Target IP/domain
            plugin (str): Plugin name
            result (Dict): Scan result data
        """
        if target not in self.scan_results:
            self.scan_results[target] = {}
        
        self.scan_results[target][plugin] = {
            'timestamp': datetime.datetime.now().isoformat(),
            'status': result.get('status', 'unknown'),
            'data': result.get('data', {}),
            'errors': result.get('errors', []),
            'duration': result.get('duration', 0)
        }
        
        logger.debug(f"Added result for {target}/{plugin}")
    
    def set_scan_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Set metadata for the scan session
        
        Args:
            metadata (Dict): Scan metadata
        """
        self.scan_metadata = {
            'scan_id': metadata.get('scan_id', 'unknown'),
            'start_time': metadata.get('start_time', datetime.datetime.now().isoformat()),
            'end_time': metadata.get('end_time', datetime.datetime.now().isoformat()),
            'targets': metadata.get('targets', []),
            'plugins_used': metadata.get('plugins_used', []),
            'total_duration': metadata.get('total_duration', 0),
            'version': metadata.get('version', '2.0.0')
        }
    
    def generate_json_report(self, filename: Optional[str] = None) -> str:
        """
        Generate JSON format report
        
        Args:
            filename (str, optional): Custom filename
            
        Returns:
            str: Path to generated report
        """
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"autorecon_report_{timestamp}.json"
        
        report_path = self.output_dir / filename
        
        report_data = {
            'metadata': self.scan_metadata,
            'results': self.scan_results,
            'summary': self._generate_summary(),
            'generated_at': datetime.datetime.now().isoformat()
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report generated: {report_path}")
        return str(report_path)
    
    def generate_html_report(self, filename: Optional[str] = None) -> str:
        """
        Generate interactive HTML report
        
        Args:
            filename (str, optional): Custom filename
            
        Returns:
            str: Path to generated report
        """
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"autorecon_report_{timestamp}.html"
        
        report_path = self.output_dir / filename
        
        html_content = self._generate_html_content()
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_path}")
        return str(report_path)
    
    def generate_xml_report(self, filename: Optional[str] = None) -> str:
        """
        Generate XML format report
        
        Args:
            filename (str, optional): Custom filename
            
        Returns:
            str: Path to generated report
        """
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"autorecon_report_{timestamp}.xml"
        
        report_path = self.output_dir / filename
        
        root = ET.Element("autorecon_report")
        
        # Metadata section
        metadata_elem = ET.SubElement(root, "metadata")
        for key, value in self.scan_metadata.items():
            elem = ET.SubElement(metadata_elem, key)
            elem.text = str(value)
        
        # Results section
        results_elem = ET.SubElement(root, "results")
        for target, plugins in self.scan_results.items():
            target_elem = ET.SubElement(results_elem, "target", name=target)
            for plugin, result in plugins.items():
                plugin_elem = ET.SubElement(target_elem, "plugin", name=plugin)
                
                status_elem = ET.SubElement(plugin_elem, "status")
                status_elem.text = result['status']
                
                timestamp_elem = ET.SubElement(plugin_elem, "timestamp")
                timestamp_elem.text = result['timestamp']
                
                data_elem = ET.SubElement(plugin_elem, "data")
                data_elem.text = json.dumps(result['data'])
        
        tree = ET.ElementTree(root)
        tree.write(report_path, encoding='utf-8', xml_declaration=True)
        
        logger.info(f"XML report generated: {report_path}")
        return str(report_path)
    
    def generate_txt_report(self, filename: Optional[str] = None) -> str:
        """
        Generate text format report
        
        Args:
            filename (str, optional): Custom filename
            
        Returns:
            str: Path to generated report
        """
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"autorecon_report_{timestamp}.txt"
        
        report_path = self.output_dir / filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self._generate_txt_content())
        
        logger.info(f"TXT report generated: {report_path}")
        return str(report_path)
    
    def generate_all_formats(self, base_filename: Optional[str] = None) -> Dict[str, str]:
        """
        Generate reports in all supported formats
        
        Args:
            base_filename (str, optional): Base filename (without extension)
            
        Returns:
            Dict[str, str]: Dictionary mapping format to file path
        """
        if not base_filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"autorecon_report_{timestamp}"
        
        reports = {}
        reports['json'] = self.generate_json_report(f"{base_filename}.json")
        reports['html'] = self.generate_html_report(f"{base_filename}.html")
        reports['xml'] = self.generate_xml_report(f"{base_filename}.xml")
        reports['txt'] = self.generate_txt_report(f"{base_filename}.txt")
        
        return reports
    
    def _generate_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics
        
        Returns:
            Dict[str, Any]: Summary statistics
        """
        total_targets = len(self.scan_results)
        total_plugins = 0
        successful_scans = 0
        failed_scans = 0
        
        findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for target, plugins in self.scan_results.items():
            total_plugins += len(plugins)
            for plugin, result in plugins.items():
                if result['status'] == 'success':
                    successful_scans += 1
                else:
                    failed_scans += 1
                
                # Count findings by severity
                if 'findings' in result['data']:
                    for finding in result['data']['findings']:
                        severity = finding.get('severity', 'info').lower()
                        if severity in findings_by_severity:
                            findings_by_severity[severity] += 1
        
        return {
            'total_targets': total_targets,
            'total_plugins_executed': total_plugins,
            'successful_scans': successful_scans,
            'failed_scans': failed_scans,
            'success_rate': round((successful_scans / total_plugins * 100) if total_plugins > 0 else 0, 2),
            'findings_by_severity': findings_by_severity,
            'total_findings': sum(findings_by_severity.values())
        }
    
    def _generate_html_content(self) -> str:
        """
        Generate HTML report content with interactive features
        
        Returns:
            str: HTML content
        """
        summary = self._generate_summary()
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoRecon-Pro Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 3px solid #007acc;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 2em;
        }}
        .summary-card p {{
            margin: 0;
            opacity: 0.9;
        }}
        .results-section {{
            margin-top: 30px;
        }}
        .target-section {{
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }}
        .target-header {{
            background: #007acc;
            color: white;
            padding: 15px;
            font-size: 1.2em;
            font-weight: bold;
        }}
        .plugin-result {{
            padding: 15px;
            border-bottom: 1px solid #eee;
        }}
        .plugin-result:last-child {{
            border-bottom: none;
        }}
        .plugin-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .plugin-name {{
            font-weight: bold;
            color: #333;
        }}
        .status {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .status.success {{
            background: #4CAF50;
            color: white;
        }}
        .status.error {{
            background: #f44336;
            color: white;
        }}
        .status.warning {{
            background: #ff9800;
            color: white;
        }}
        .finding {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 10px;
            margin: 5px 0;
        }}
        .finding.critical {{
            background: #f8d7da;
            border-color: #f5c6cb;
        }}
        .finding.high {{
            background: #fff3cd;
            border-color: #ffeaa7;
        }}
        .finding.medium {{
            background: #cce5ff;
            border-color: #b3d9ff;
        }}
        .finding.low {{
            background: #d4edda;
            border-color: #c3e6cb;
        }}
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        .collapsible:hover {{
            background-color: #f0f0f0;
        }}
        .content {{
            display: none;
            padding: 10px;
            background-color: #f9f9f9;
        }}
        .content.active {{
            display: block;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 AutoRecon-Pro Scan Report</h1>
            <p>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>{summary['total_targets']}</h3>
                <p>Targets Scanned</p>
            </div>
            <div class="summary-card">
                <h3>{summary['total_plugins_executed']}</h3>
                <p>Plugins Executed</p>
            </div>
            <div class="summary-card">
                <h3>{summary['success_rate']}%</h3>
                <p>Success Rate</p>
            </div>
            <div class="summary-card">
                <h3>{summary['total_findings']}</h3>
                <p>Total Findings</p>
            </div>
        </div>
        
        <div class="results-section">
            <h2>📊 Scan Results</h2>
            {self._generate_html_results()}
        </div>
    </div>
    
    <script>
        // Toggle collapsible content
        document.querySelectorAll('.collapsible').forEach(item => {{
            item.addEventListener('click', function() {{
                const content = this.nextElementSibling;
                content.classList.toggle('active');
            }});
        }});
        
        // Auto-expand sections with findings
        document.querySelectorAll('.finding').forEach(finding => {{
            const content = finding.closest('.content');
            if (content) {{
                content.classList.add('active');
            }}
        }});
    </script>
</body>
</html>
        """
        
        return html_template
    
    def _generate_html_results(self) -> str:
        """
        Generate HTML results section
        
        Returns:
            str: HTML results content
        """
        html_results = ""
        
        for target, plugins in self.scan_results.items():
            html_results += f"""
            <div class="target-section">
                <div class="target-header">🎯 {target}</div>
            """
            
            for plugin, result in plugins.items():
                status_class = 'success' if result['status'] == 'success' else 'error'
                
                html_results += f"""
                <div class="plugin-result">
                    <div class="plugin-header collapsible">
                        <span class="plugin-name">🔧 {plugin}</span>
                        <div>
                            <span class="status {status_class}">{result['status']}</span>
                            <span class="timestamp">{result['timestamp']}</span>
                        </div>
                    </div>
                    <div class="content">
                """
                
                # Add findings if present
                if 'findings' in result['data'] and result['data']['findings']:
                    for finding in result['data']['findings']:
                        severity = finding.get('severity', 'info').lower()
                        html_results += f"""
                        <div class="finding {severity}">
                            <strong>{finding.get('title', 'Finding')}</strong><br>
                            {finding.get('description', 'No description available')}
                        </div>
                        """
                
                # Add raw data
                if result['data']:
                    html_results += f"""
                    <pre style="background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto;">
{json.dumps(result['data'], indent=2)}
                    </pre>
                    """
                
                html_results += """
                    </div>
                </div>
                """
            
            html_results += "</div>"
        
        return html_results
    
    def _generate_txt_content(self) -> str:
        """
        Generate text report content
        
        Returns:
            str: Text content
        """
        content = []
        content.append("=" * 80)
        content.append("AUTORECON-PRO SCAN REPORT")
        content.append("=" * 80)
        content.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append("")
        
        # Metadata
        if self.scan_metadata:
            content.append("SCAN METADATA")
            content.append("-" * 40)
            for key, value in self.scan_metadata.items():
                content.append(f"{key.upper().replace('_', ' ')}: {value}")
            content.append("")
        
        # Summary
        summary = self._generate_summary()
        content.append("SUMMARY")
        content.append("-" * 40)
        content.append(f"Targets Scanned: {summary['total_targets']}")
        content.append(f"Plugins Executed: {summary['total_plugins_executed']}")
        content.append(f"Success Rate: {summary['success_rate']}%")
        content.append(f"Total Findings: {summary['total_findings']}")
        content.append("")
        
        # Results
        content.append("DETAILED RESULTS")
        content.append("-" * 40)
        
        for target, plugins in self.scan_results.items():
            content.append(f"\nTARGET: {target}")
            content.append("=" * (len(target) + 8))
            
            for plugin, result in plugins.items():
                content.append(f"\nPlugin: {plugin}")
                content.append(f"Status: {result['status']}")
                content.append(f"Timestamp: {result['timestamp']}")
                content.append(f"Duration: {result['duration']}s")
                
                if 'findings' in result['data'] and result['data']['findings']:
                    content.append("Findings:")
                    for finding in result['data']['findings']:
                        content.append(f"  - [{finding.get('severity', 'INFO')}] {finding.get('title', 'Unknown')}")
                        content.append(f"    {finding.get('description', 'No description')}")
                
                if result['errors']:
                    content.append("Errors:")
                    for error in result['errors']:
                        content.append(f"  - {error}")
                
                content.append("-" * 60)
        
        return "\n".join(content)