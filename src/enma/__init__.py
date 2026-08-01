"""enma — Android runtime analysis and research toolkit, powered by Frida."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("enma")
except PackageNotFoundError:  # source tree without an install
    __version__ = "0.0.0.dev0"
