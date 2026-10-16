#!/usr/bin/env python3
"""Check normalization against native generated syntax, preserving other version metadata [D243], #201."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

spec = spec_from_file_location("metadata", Path(__file__).with_name("normalize-native-metadata.py"))
module = module_from_spec(spec)
spec.loader.exec_module(module)
header = '''#define PLATFORM "platform: linux-x86_64"
#define DATE "built on: Thu Jan  1 00:00:00 1970 UTC"
static const char compiler_flags[] = {
    'c','o','m','p','i','l','e','r',':',' ','/','a','/',
'\\0'
};
'''
other = header.replace("'a'", "'b','b','b','b'")
normalized = module.normalize(header)
assert normalized == module.normalize(other)
assert 'PLATFORM "platform: linux-x86_64"' in normalized
assert 'DATE "built on: Thu Jan  1 00:00:00 1970 UTC"' in normalized
assert module.normalize(normalized) == normalized
try:
    module.normalize("unexpected header")
except ValueError:
    pass
else:
    raise AssertionError("changed upstream syntax must refuse normalization")
print("native compiler metadata: path independent; platform/date retained; unexpected syntax refused")
