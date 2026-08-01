"""Shared primitives used by the feature modules.

Nothing in this package may import from ``enma.cli`` or from a feature module —
the dependency arrow runs ``cli -> feature modules -> core`` and never back.
"""
