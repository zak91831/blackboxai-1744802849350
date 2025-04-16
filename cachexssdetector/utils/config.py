"""
Configuration management for CacheXSSDetector.
Handles loading, validation, and access to configuration settings.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from .logger import get_logger

logger = get_logger(__name__)

# Default configuration settings
DEFAULT_CONFIG = {
    'scanner': {
        'timeout': 30,
        'max_retries': 3,
        'user_agent': 'CacheXSSDetector/1.0',
        'threads': 5,
        'delay': 0.5
    },
    'payloads': {
        'max_length': 1000,
        'encode_payload': True,
        'test_all_methods': False
    },
    'cache': {
        'detection_threshold': 0.8,
        'verification_requests': 3,
        'cache_timeout': 300
    },
    'reporting': {
        'include_headers': True,
        'include_response': False,
        'max_response_size': 1024 * 1024,  # 1MB
        'output_format': 'json'
    },
    'proxy': {
        'enabled': False,
        'http': None,
        'https': None,
        'verify_ssl': True
    },
    'alerts': {
        'enabled': True,
        'min_severity': 'medium',
        'notification_method': 'console'
    }
}

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from a YAML file and merge with defaults.
    
    Args:
        config_path (Optional[str]): Path to configuration file
        
    Returns:
        Dict[str, Any]: Merged configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_path:
        try:
            config_file = Path(config_path)
            
            if not config_file.exists():
                logger.warning(f"Configuration file not found: {config_path}")
                return config
                
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                
            if user_config:
                # Deep merge user configuration with defaults
                config = deep_merge(config, user_config)
                logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
            return config
    
    # Load environment variables that override config
    config = load_env_config(config)
    
    return config

def deep_merge(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries, updating base with values from update.
    
    Args:
        base (Dict[str, Any]): Base dictionary
        update (Dict[str, Any]): Dictionary to merge into base
        
    Returns:
        Dict[str, Any]: Merged dictionary
    """
    for key, value in update.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base

def load_env_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load configuration from environment variables.
    Environment variables should be prefixed with 'CACHEXSS_'.
    
    Args:
        config (Dict[str, Any]): Existing configuration dictionary
        
    Returns:
        Dict[str, Any]: Updated configuration dictionary
    """
    env_prefix = 'CACHEXSS_'
    
    for env_key, env_value in os.environ.items():
        if env_key.startswith(env_prefix):
            # Remove prefix and split into config path
            config_path = env_key[len(env_prefix):].lower().split('_')
            
            # Navigate to the correct config location
            current = config
            for path_part in config_path[:-1]:
                if path_part not in current:
                    current[path_part] = {}
                current = current[path_part]
            
            # Set the value, converting to appropriate type
            try:
                # Try to convert to int or float if possible
                if env_value.isdigit():
                    env_value = int(env_value)
                elif env_value.replace('.', '').isdigit() and env_value.count('.') == 1:
                    env_value = float(env_value)
                elif env_value.lower() in ('true', 'false'):
                    env_value = env_value.lower() == 'true'
                    
                current[config_path[-1]] = env_value
                logger.debug(f"Loaded config from environment: {env_key}")
            except Exception as e:
                logger.warning(f"Failed to parse environment variable {env_key}: {str(e)}")
    
    return config

def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration values.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary to validate
        
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    try:
        # Validate scanner settings
        if not isinstance(config['scanner']['timeout'], (int, float)) or config['scanner']['timeout'] <= 0:
            logger.error("Invalid scanner timeout value")
            return False
            
        if not isinstance(config['scanner']['max_retries'], int) or config['scanner']['max_retries'] < 0:
            logger.error("Invalid max_retries value")
            return False
            
        # Validate payload settings
        if not isinstance(config['payloads']['max_length'], int) or config['payloads']['max_length'] <= 0:
            logger.error("Invalid payload max_length value")
            return False
            
        # Validate cache settings
        if not isinstance(config['cache']['detection_threshold'], (int, float)) or \
           not 0 <= config['cache']['detection_threshold'] <= 1:
            logger.error("Invalid cache detection_threshold value")
            return False
            
        return True
    except KeyError as e:
        logger.error(f"Missing required configuration key: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Configuration validation failed: {str(e)}")
        return False

def save_config(config: Dict[str, Any], config_path: str) -> bool:
    """
    Save configuration to a YAML file.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary to save
        config_path (str): Path to save configuration file
        
    Returns:
        bool: True if save successful, False otherwise
    """
    try:
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False)
            
        logger.info(f"Configuration saved to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save configuration: {str(e)}")
        return False

if __name__ == "__main__":
    # Test configuration loading and validation
    config = load_config()
    if validate_config(config):
        print("Configuration validation successful")
        print(yaml.dump(config, default_flow_style=False))
