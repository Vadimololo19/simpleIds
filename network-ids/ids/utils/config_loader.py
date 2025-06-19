import yaml
import os

def load_config(config_path="/../home/Kaguya/petProjects/simpleIds/network-ids/config.yaml"):
    config_path = os.path.expanduser(config_path)

    config_path = os.path.abspath(config_path)

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    print(f"[*] Loading config from: {config_path}")

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    return config
