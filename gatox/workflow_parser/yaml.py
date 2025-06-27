from ruamel.yaml import YAML

yaml_loader = YAML(typ=["safe", "rt", "string"])


def parse_yaml(yaml_str: str | bytes):
    if type(yaml_str) is bytes:
        yaml_str = yaml_str.decode("utf-8")
    return yaml_loader.load(yaml_str.replace("\t", "  "))


def dump_yaml(data) -> str:
    return yaml_loader.dump_to_string(data)
