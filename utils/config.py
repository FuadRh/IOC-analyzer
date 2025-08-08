# utils/config.py
import os
from dotenv import load_dotenv

def _initialize_config():
    """
    FIX: This function is now more flexible.
    It loads environment variables from a .env file if it exists, but does NOT
    fail if the file is missing. This allows the app to work locally (with a file)
    and in Docker (where variables are passed directly into the environment).
    """
    dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)
    # If the .env file doesn't exist, we proceed, assuming that the
    # environment variables have been set by other means (like Docker Compose).

def get_config_value(key: str) -> str:
    """
    Retrieves a configuration value from the loaded environment variables.
    This function will now correctly find variables set by Docker Compose.
    """
    value = os.getenv(key)
    if not value or "YOUR_" in value:
        # This error will now trigger if the variable is missing from the .env file
        # OR if it wasn't passed to the Docker container correctly.
        raise ValueError(f"Configuration value for '{key}' not found or is not set in your environment.")
    return value

# Automatically load the environment when this module is imported.
_initialize_config()
