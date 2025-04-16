"""
Commenting System for CacheXSSDetector.
Enables commenting on vulnerability reports for team collaboration.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)

class CommentingSystem:
    """
    Manages comments on vulnerability reports.
    """

    def __init__(self, comments_dir: Optional[str] = None):
        """
        Initialize commenting system.
        
        Args:
            comments_dir (Optional[str]): Directory to store comments
        """
        self.comments_dir = Path(comments_dir) if comments_dir else Path.home() / ".cachexssdetector" / "comments"
        self.comments_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Comments directory set to: {self.comments_dir}")

    def _get_comments_file(self, report_name: str) -> Path:
        """
        Get the path to the comments file for a report.
        
        Args:
            report_name (str): Name of the report file
            
        Returns:
            Path: Path to the comments JSON file
        """
        return self.comments_dir / f"{report_name}.comments.json"

    def add_comment(self, report_name: str, user: str, comment: str) -> bool:
        """
        Add a comment to a report.
        
        Args:
            report_name (str): Name of the report file
            user (str): Username of the commenter
            comment (str): Comment text
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            comments_file = self._get_comments_file(report_name)
            comments = self.get_comments(report_name) or []
            comment_entry = {
                "user": user,
                "comment": comment,
                "timestamp": datetime.utcnow().isoformat()
            }
            comments.append(comment_entry)
            with open(comments_file, 'w') as f:
                json.dump(comments, f, indent=4)
            logger.info(f"Added comment to {report_name} by {user}")
            return True
        except Exception as e:
            logger.error(f"Failed to add comment: {str(e)}")
            return False

    def get_comments(self, report_name: str) -> Optional[List[Dict]]:
        """
        Retrieve comments for a report.
        
        Args:
            report_name (str): Name of the report file
            
        Returns:
            Optional[List[Dict]]: List of comments or None if none exist
        """
        try:
            comments_file = self._get_comments_file(report_name)
            if not comments_file.exists():
                return []
            with open(comments_file, 'r') as f:
                comments = json.load(f)
            return comments
        except Exception as e:
            logger.error(f"Failed to get comments: {str(e)}")
            return None

if __name__ == "__main__":
    commenting_system = CommentingSystem()
    report = "sample_report.json"
    commenting_system.add_comment(report, "alice", "This vulnerability needs urgent attention.")
    comments = commenting_system.get_comments(report)
    print(f"Comments for {report}:")
    for c in comments:
        print(f"{c['timestamp']} - {c['user']}: {c['comment']}")
