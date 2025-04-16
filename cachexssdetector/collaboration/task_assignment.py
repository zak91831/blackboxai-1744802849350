"""
Task Assignment for Remediation Module for CacheXSSDetector.
Allows assigning and tracking remediation tasks based on vulnerability reports.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)

class TaskAssignment:
    """
    Manages task assignments for vulnerability remediation.
    """

    def __init__(self, tasks_dir: Optional[str] = None):
        """
        Initialize task assignment manager.
        
        Args:
            tasks_dir (Optional[str]): Directory to store task files
        """
        self.tasks_dir = Path(tasks_dir) if tasks_dir else Path.home() / ".cachexssdetector" / "tasks"
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Tasks directory set to: {self.tasks_dir}")

    def _get_tasks_file(self, report_name: str) -> Path:
        """
        Get the path to the tasks file for a report.
        
        Args:
            report_name (str): Name of the report file
            
        Returns:
            Path: Path to the tasks JSON file
        """
        return self.tasks_dir / f"{report_name}.tasks.json"

    def assign_task(self, report_name: str, task: str, assignee: str, due_date: Optional[str] = None) -> bool:
        """
        Assign a remediation task.
        
        Args:
            report_name (str): Name of the report file
            task (str): Task description
            assignee (str): Person assigned to the task
            due_date (Optional[str]): Due date in ISO format
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            tasks_file = self._get_tasks_file(report_name)
            tasks = self.get_tasks(report_name) or []
            task_entry = {
                "task": task,
                "assignee": assignee,
                "due_date": due_date,
                "status": "open",
                "created_at": datetime.utcnow().isoformat()
            }
            tasks.append(task_entry)
            with open(tasks_file, 'w') as f:
                json.dump(tasks, f, indent=4)
            logger.info(f"Assigned task to {assignee} for report {report_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to assign task: {str(e)}")
            return False

    def get_tasks(self, report_name: str) -> Optional[List[Dict]]:
        """
        Retrieve tasks for a report.
        
        Args:
            report_name (str): Name of the report file
            
        Returns:
            Optional[List[Dict]]: List of tasks or None if none exist
        """
        try:
            tasks_file = self._get_tasks_file(report_name)
            if not tasks_file.exists():
                return []
            with open(tasks_file, 'r') as f:
                tasks = json.load(f)
            return tasks
        except Exception as e:
            logger.error(f"Failed to get tasks: {str(e)}")
            return None

    def update_task_status(self, report_name: str, task_index: int, status: str) -> bool:
        """
        Update the status of a task.
        
        Args:
            report_name (str): Name of the report file
            task_index (int): Index of the task in the list
            status (str): New status (e.g., 'open', 'in_progress', 'closed')
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            tasks = self.get_tasks(report_name)
            if tasks is None or task_index < 0 or task_index >= len(tasks):
                logger.error(f"Invalid task index {task_index} for report {report_name}")
                return False
            tasks[task_index]['status'] = status
            tasks_file = self._get_tasks_file(report_name)
            with open(tasks_file, 'w') as f:
                json.dump(tasks, f, indent=4)
            logger.info(f"Updated task {task_index} status to {status} for report {report_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to update task status: {str(e)}")
            return False

if __name__ == "__main__":
    task_manager = TaskAssignment()
    report = "sample_report.json"
    task_manager.assign_task(report, "Fix XSS vulnerability in login page", "bob", "2023-12-31")
    tasks = task_manager.get_tasks(report)
    print(f"Tasks for {report}:")
    for i, t in enumerate(tasks):
        print(f"{i}. {t['task']} assigned to {t['assignee']} - Status: {t['status']}")
