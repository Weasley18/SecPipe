import yaml


def bad(data):
    # ruleid: secnotes-unsafe-yaml-load
    return yaml.load(data, Loader=yaml.Loader)


def bad_default(data):
    # ruleid: secnotes-unsafe-yaml-load
    return yaml.load(data)


def bad_unsafe(data):
    # ruleid: secnotes-unsafe-yaml-load
    return yaml.unsafe_load(data)


def good(data):
    # ok: secnotes-unsafe-yaml-load
    return yaml.safe_load(data)


def good_explicit(data):
    # ok: secnotes-unsafe-yaml-load
    return yaml.load(data, Loader=yaml.SafeLoader)
