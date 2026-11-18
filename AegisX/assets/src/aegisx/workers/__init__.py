"""AegisX background workers (QThreadPool based)."""

from .task_manager import TaskManager, Worker

__all__ = ["TaskManager", "Worker"]
