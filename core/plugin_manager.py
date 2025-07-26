#!/usr/bin/env python3
"""
AutoRecon-Py Pro - Plugin Management System
"""

import os
import importlib
import inspect
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type
from pathlib import Path
import json
import yaml

class PluginBase(ABC):
    """Base class for all plugins"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.name = self.__class__.__name__
        self.results = {}
        self.errors = []
        self.patterns = []
        self.manual_commands = []
    
    @property
    @abstractmethod
    def plugin_type(self) -> str:
        """Plugin type (port_scan, service_scan, etc.)"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass
    
    @property
    @abstractmethod
    def dependencies(self) -> List[str]:
        """Required system dependencies"""
        pass
    
    @property
    def tags(self) -> List[str]:
        """Plugin tags for filtering"""
        return ['default']
    
    @property
    def priority(self) -> int:
        """Plugin execution priority (lower = higher priority)"""
        return 100
    
    @abstractmethod
    async def run(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Main plugin execution method"""
        pass
    
    def should_run(self, target_info: Dict[str, Any]) -> bool:
        """Determine if plugin should run for target"""
        return True
    
    def parse_output(self, output: str, command: str = "") -> Dict[str, Any]:
        """Parse command output and extract results"""
        return {'raw_output': output}
    
    def extract_patterns(self, text: str) -> List[Dict[str, str]]:
        """Extract interesting patterns from text"""
        matches = []
        for pattern_type, patterns in self.config.get('patterns', {}).items():
            for pattern in patterns:
                import re
                for match in re.finditer(pattern, text):
                    matches.append({
                        'type': pattern_type,
                        'match': match.group(),
                        'context': text[max(0, match.start()-50):match.end()+50]
                    })
        return matches
    
    def add_manual_command(self, command: str, description: str):
        """Add manual command for later execution"""
        self.manual_commands.append({
            'command': command,
            'description': description,
            'plugin': self.name
        })
    
    def log_finding(self, finding_type: str, details: str, severity: str = 'INFO'):
        """Log a finding"""
        self.logger.finding(finding_type, details, severity)
        
class PortScanPlugin(PluginBase):
    """Base class for port scanning plugins"""
    
    @property
    def plugin_type(self) -> str:
        return 'port_scan'

class ServiceScanPlugin(PluginBase):
    """Base class for service scanning plugins"""
    
    @property
    def plugin_type(self) -> str:
        return 'service_scan'

class VulnerabilityScanPlugin(PluginBase):
    """Base class for vulnerability scanning plugins"""
    
    @property
    def plugin_type(self) -> str:
        return 'vuln_scan'

class ReportPlugin(PluginBase):
    """Base class for reporting plugins"""
    
    @property
    def plugin_type(self) -> str:
        return 'report'

class PluginManager:
    """Advanced plugin management system"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.plugins = {}
        self.plugin_instances = {}
        self.load_plugins()
    
    def load_plugins(self):
        """Load all available plugins"""
        # Load built-in plugins
        self._load_builtin_plugins()
        
        # Load custom plugins
        custom_path = self.config.get('plugins.custom_path')
        if custom_path and os.path.exists(custom_path):
            self._load_custom_plugins(custom_path)
        
        self.logger.info(f"Loaded {len(self.plugins)} plugins")
    
    def _load_builtin_plugins(self):
        """Load built-in plugins"""
        plugin_dir = Path(__file__).parent.parent / 'plugins'
        if plugin_dir.exists():
            self._load_plugins_from_directory(plugin_dir)
    
    def _load_custom_plugins(self, plugin_path: str):
        """Load custom plugins from specified path"""
        custom_dir = Path(plugin_path)
        if custom_dir.exists():
            self._load_plugins_from_directory(custom_dir)
    
    def _load_plugins_from_directory(self, plugin_dir: Path):
        """Load plugins from a directory"""
        for plugin_file in plugin_dir.glob('*.py'):
            if plugin_file.name.startswith('_'):
                continue
                
            try:
                # Import plugin module
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find plugin classes
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, PluginBase) and 
                        obj != PluginBase and
                        not obj.__name__.endswith('Plugin')):
                        
                        self.plugins[obj.__name__] = obj
                        self.logger.debug(f"Loaded plugin: {obj.__name__}")
                        
            except Exception as e:
                self.logger.error(f"Failed to load plugin {plugin_file}: {e}")
    
    def get_available_plugins(self) -> Dict[str, List[Dict[str, str]]]:
        """Get list of available plugins by category"""
        categories = {}
        
        for plugin_name, plugin_class in self.plugins.items():
            # Create temporary instance to get metadata
            try:
                instance = plugin_class(self.config, self.logger)
                plugin_type = instance.plugin_type
                
                if plugin_type not in categories:
                    categories[plugin_type] = []
                
                categories[plugin_type].append({
                    'name': plugin_name,
                    'description': instance.description,
                    'tags': instance.tags,
                    'dependencies': instance.dependencies
                })
            except Exception as e:
                self.logger.error(f"Error getting plugin info for {plugin_name}: {e}")
        
        return categories
    
    def get_plugins_for_target(self, target_info: Dict[str, Any], 
                              plugin_filter: Optional[List[str]] = None,
                              exclude_filter: Optional[List[str]] = None) -> List[PluginBase]:
        """Get plugins that should run for a specific target"""
        selected_plugins = []
        
        for plugin_name, plugin_class in self.plugins.items():
            try:
                # Create plugin instance
                instance = plugin_class(self.config, self.logger)
                
                # Apply filters
                if plugin_filter and plugin_name not in plugin_filter:
                    continue
                    
                if exclude_filter and plugin_name in exclude_filter:
                    continue
                
                # Check if plugin should run for this target
                if instance.should_run(target_info):
                    selected_plugins.append(instance)
                    
            except Exception as e:
                self.logger.error(f"Error initializing plugin {plugin_name}: {e}")
        
        # Sort by priority
        selected_plugins.sort(key=lambda p: p.priority)
        
        return selected_plugins
    
    def get_plugins_by_type(self, plugin_type: str) -> List[PluginBase]:
        """Get all plugins of a specific type"""
        plugins = []
        
        for plugin_name, plugin_class in self.plugins.items():
            try:
                instance = plugin_class(self.config, self.logger)
                if instance.plugin_type == plugin_type:
                    plugins.append(instance)
            except Exception as e:
                self.logger.error(f"Error getting plugin {plugin_name}: {e}")
        
        return sorted(plugins, key=lambda p: p.priority)
    
    def validate_dependencies(self) -> Dict[str, List[str]]:
        """Validate plugin dependencies"""
        missing_deps = {}
        
        for plugin_name, plugin_class in self.plugins.items():
            try:
                instance = plugin_class(self.config, self.logger)
                missing = []
                
                for dep in instance.dependencies:
                    if not self._check_dependency(dep):
                        missing.append(dep)
                
                if missing:
                    missing_deps[plugin_name] = missing
                    
            except Exception as e:
                self.logger.error(f"Error checking dependencies for {plugin_name}: {e}")
        
        return missing_deps
    
    def _check_dependency(self, dependency: str) -> bool:
        """Check if a dependency is available"""
        import shutil
        return shutil.which(dependency) is not None
    
    async def run_plugin(self, plugin: PluginBase, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single plugin"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            self.logger.plugin_start(plugin.name, target_info.get('target', 'unknown'))
            
            # Run plugin with timeout
            timeout = self.config.get('plugins.timeout', 300)
            result = await asyncio.wait_for(plugin.run(target_info), timeout=timeout)
            
            # Calculate duration
            duration = asyncio.get_event_loop().time() - start_time
            
            # Log completion
            results_count = len(result.get('results', []))
            self.logger.plugin_complete(plugin.name, target_info.get('target', 'unknown'), results_count)
            
            # Add metadata
            result['plugin_name'] = plugin.name
            result['plugin_type'] = plugin.plugin_type
            result['duration'] = duration
            result['timestamp'] = asyncio.get_event_loop().time()
            result['manual_commands'] = plugin.manual_commands
            result['patterns'] = plugin.patterns
            result['errors'] = plugin.errors
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.error(f"Plugin {plugin.name} timed out after {timeout}s")
            return {'error': 'timeout', 'plugin_name': plugin.name}
            
        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            self.logger.error(f"Plugin {plugin.name} failed: {e}")
            return {
                'error': str(e),
                'plugin_name': plugin.name,
                'duration': duration
            }
    
    async def run_plugins_parallel(self, plugins: List[PluginBase], 
                                 target_info: Dict[str, Any],
                                 max_concurrent: int = 5) -> List[Dict[str, Any]]:
        """Run multiple plugins in parallel"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_with_semaphore(plugin):
            async with semaphore:
                return await self.run_plugin(plugin, target_info)
        
        # Create tasks for all plugins
        tasks = [run_with_semaphore(plugin) for plugin in plugins]
        
        # Wait for all plugins to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Plugin execution error: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a plugin"""
        if plugin_name not in self.plugins:
            return None
        
        try:
            plugin_class = self.plugins[plugin_name]
            instance = plugin_class(self.config, self.logger)
            
            return {
                'name': plugin_name,
                'type': instance.plugin_type,
                'description': instance.description,
                'tags': instance.tags,
                'priority': instance.priority,
                'dependencies': instance.dependencies,
                'class_name': plugin_class.__name__,
                'module': plugin_class.__module__
            }
        except Exception as e:
            self.logger.error(f"Error getting plugin info for {plugin_name}: {e}")
            return None
    
    def export_plugin_config(self, output_file: str):
        """Export plugin configuration to file"""
        config_data = {
            'plugins': {},
            'metadata': {
                'total_plugins': len(self.plugins),
                'export_timestamp': asyncio.get_event_loop().time()
            }
        }
        
        for plugin_name, plugin_class in self.plugins.items():
            try:
                instance = plugin_class(self.config, self.logger)
                config_data['plugins'][plugin_name] = {
                    'type': instance.plugin_type,
                    'description': instance.description,
                    'tags': instance.tags,
                    'priority': instance.priority,
                    'dependencies': instance.dependencies,
                    'enabled': True
                }
            except Exception as e:
                self.logger.error(f"Error exporting config for {plugin_name}: {e}")
        
        try:
            with open(output_file, 'w') as f:
                if output_file.endswith('.yaml') or output_file.endswith('.yml'):
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_data, f, indent=2)
            
            self.logger.success(f"Plugin configuration exported to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to export plugin config: {e}")