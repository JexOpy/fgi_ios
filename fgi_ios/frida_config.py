"""Built-in Frida Gadget configuration templates."""

import json

# Config type: listen — app runs, Frida connects via USB later
LISTEN_CONFIG = {
    "interaction": {
        "type": "listen",
        "address": "0.0.0.0",
        "port": 27042,
        "on_port_conflict": "fail",
        "on_load": "wait",
    }
}

# Config type: connect — gadget connects to a remote Frida server
CONNECT_CONFIG = {
    "interaction": {
        "type": "connect",
        "address": "0.0.0.0",
        "port": 27052,
    }
}


def get_script_config(script_name: str) -> dict:
    """Config type: script — loads a JS script at startup."""
    return {
        "interaction": {
            "type": "script",
            "path": script_name,
        }
    }


CONFIG_TYPES = {
    "listen": LISTEN_CONFIG,
    "connect": CONNECT_CONFIG,
}


def get_config_content(config_type: str, script_name: str = "agent.js") -> str:
    """Get JSON config content for the given type."""
    if config_type == "script":
        config = get_script_config(script_name)
    elif config_type in CONFIG_TYPES:
        config = CONFIG_TYPES[config_type]
    else:
        raise ValueError(f"Unknown config type: {config_type}")
    return json.dumps(config, indent=2) + "\n"
