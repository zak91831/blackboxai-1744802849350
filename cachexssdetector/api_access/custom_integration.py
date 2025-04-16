"""
Custom Integration Capabilities for CacheXSSDetector.
Provides hooks and interfaces for integrating with external tools and systems.
"""

from typing import Callable, Optional, Dict, Any
from ..utils.logger import get_logger

logger = get_logger(__name__)

class CustomIntegration:
    """
    Provides integration hooks for external tools.
    """

    def __init__(self):
        self.pre_scan_hook: Optional[Callable[[Dict[str, Any]], None]] = None
        self.post_scan_hook: Optional[Callable[[Dict[str, Any]], None]] = None

    def set_pre_scan_hook(self, hook: Callable[[Dict[str, Any]], None]):
        """
        Set a hook to be called before scanning.
        
        Args:
            hook (Callable[[Dict[str, Any]], None]): Hook function
        """
        self.pre_scan_hook = hook
        logger.info("Pre-scan hook set.")

    def set_post_scan_hook(self, hook: Callable[[Dict[str, Any]], None]):
        """
        Set a hook to be called after scanning.
        
        Args:
            hook (Callable[[Dict[str, Any]], None]): Hook function
        """
        self.post_scan_hook = hook
        logger.info("Post-scan hook set.")

    def execute_pre_scan(self, context: Dict[str, Any]):
        """
        Execute the pre-scan hook.
        
        Args:
            context (Dict[str, Any]): Contextual information
        """
        if self.pre_scan_hook:
            try:
                self.pre_scan_hook(context)
                logger.info("Pre-scan hook executed.")
            except Exception as e:
                logger.error(f"Error executing pre-scan hook: {str(e)}")

    def execute_post_scan(self, context: Dict[str, Any]):
        """
        Execute the post-scan hook.
        
        Args:
            context (Dict[str, Any]): Contextual information
        """
        if self.post_scan_hook:
            try:
                self.post_scan_hook(context)
                logger.info("Post-scan hook executed.")
            except Exception as e:
                logger.error(f"Error executing post-scan hook: {str(e)}")

if __name__ == "__main__":
    def pre_scan(context):
        print("Pre-scan hook called with context:", context)

    def post_scan(context):
        print("Post-scan hook called with context:", context)

    integration = CustomIntegration()
    integration.set_pre_scan_hook(pre_scan)
    integration.set_post_scan_hook(post_scan)

    integration.execute_pre_scan({"url": "http://example.com"})
    integration.execute_post_scan({"result": "success"})
