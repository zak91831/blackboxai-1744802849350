"""
Shared Reports Module for CacheXSSDetector.
Allows sharing of reports among team members by exporting and importing report files.
"""

import os
import shutil
from pathlib import Path
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class SharedReports:
    """
    Handles sharing and management of vulnerability reports.
    """

    def __init__(self, shared_dir: Optional[str] = None):
        """
        Initialize shared reports manager.
        
        Args:
            shared_dir (Optional[str]): Directory path to store shared reports
        """
        self.shared_dir = Path(shared_dir) if shared_dir else Path.home() / ".cachexssdetector" / "shared_reports"
        self.shared_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Shared reports directory set to: {self.shared_dir}")

    def share_report(self, report_path: str) -> Optional[str]:
        """
        Share a report by copying it to the shared directory.
        
        Args:
            report_path (str): Path to the report file
            
        Returns:
            Optional[str]: Path to the shared report or None if failed
        """
        try:
            report_file = Path(report_path)
            if not report_file.exists():
                logger.error(f"Report file does not exist: {report_path}")
                return None
            
            dest_path = self.shared_dir / report_file.name
            shutil.copy2(report_file, dest_path)
            logger.info(f"Report shared at: {dest_path}")
            return str(dest_path)
        except Exception as e:
            logger.error(f"Failed to share report: {str(e)}")
            return None

    def list_shared_reports(self) -> list:
        """
        List all shared reports.
        
        Returns:
            list: List of shared report filenames
        """
        try:
            reports = [f.name for f in self.shared_dir.glob("*.json")]
            logger.info(f"Found {len(reports)} shared reports")
            return reports
        except Exception as e:
            logger.error(f"Failed to list shared reports: {str(e)}")
            return []

    def get_report_path(self, report_name: str) -> Optional[str]:
        """
        Get the full path of a shared report by name.
        
        Args:
            report_name (str): Name of the report file
            
        Returns:
            Optional[str]: Full path or None if not found
        """
        try:
            report_path = self.shared_dir / report_name
            if report_path.exists():
                return str(report_path)
            else:
                logger.error(f"Shared report not found: {report_name}")
                return None
        except Exception as e:
            logger.error(f"Error getting report path: {str(e)}")
            return None

if __name__ == "__main__":
    shared_reports = SharedReports()
    print("Shared reports:", shared_reports.list_shared_reports())
