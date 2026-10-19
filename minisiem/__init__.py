"""Mini SIEM — a small security event correlation engine.

Pipeline: generate -> parse/load (SQLite) -> detect (sliding windows) -> evaluate.
"""

__version__ = "0.1.0"
