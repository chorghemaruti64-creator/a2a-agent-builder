"""
Pytest configuration and fixtures for A2A tests.
"""

import pytest
import sys
from pathlib import Path

# Add reference to path
sys.path.insert(0, str(Path(__file__).parent.parent))
