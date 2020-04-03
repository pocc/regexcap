#!/usr/bin/env python3
"""
  Ross Jacobs, 2020, tshark.dev
  This script, provided the SSID and secret, will replace
  encrypted data bytes with the unencrypted data bytes.
  After completion, it should print the number of packets modified

  WARNING: This program will be slow! It uses python with a naive algorithm.
"""
import argparse
import atexit
import json
import os
import re
import shutil
import subprocess as sp
import sys


TEMP_FILE = ".temp.pcapng"


def check_tshark():
    """Check whether tshark can be used."""
    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        raise OSError("Unable to find tshark. Check your PATH & installation.")


def get_args():
    """Args:
    # 1. File
    # 2. Field
    # 3. From
    # 4. To

    # If from, and to are all present, replace from with to
    # If from DNE, then replace all instances of field with to """
    desc = "Replace pcap fields with regex"
    parser = argparse.ArgumentParser(prog="regexcap", description=desc)
    parser.epilog = """

    ### Usage notes

    * This program will be slow! It uses python with a naive algorithm (i.e. it works)
    * -Y creates a temporary file that is read from that is deleted on exit
    * This replaces bytes in packets, not on packet or pcap headers

    ### Contact

    Ross Jacobs, rj[AT]swit.sh
    https://github.com/pocc/regexcap
    """

    _help = {
        "-r": "input file. Use - for stdin",
        "-w": "output file. Use - for stdout",
        "-e": "field to change. Multiple fields can be specified like "
        "`-e ip.src -e ip.dst`. Replacements will occur on all "
        "specified fields. If `frame` is specified, matching frames"
        "will be replaced in their entirety.",
        "-s": 'source field bytes regex. Defaults to regex ".*" if no arg is provided.',
        "-d": "destination field bytes",
        "-Y": "Before replacing bytes, delete packets that do not match this display filter",
    }

    parser.add_argument("-r", action="store", help=_help["-r"], required=True)
    parser.add_argument("-w", action="store", help=_help["-w"], required=True)
    parser.add_argument("-e", action="append", help=_help["-e"], required=True)
    parser.add_argument("-s", action="store", help=_help["-s"], default=".*")
    parser.add_argument("-d", action="store", help=_help["-d"], required=True)
    parser.add_argument("-Y", action="store", help=_help["-Y"])
    args = vars(parser.parse_args())
    # Remove encapsulating single/double quotes around any argument
    for arg in args:
        if args[arg] and len(args[arg]) > 2:
            if args[arg][0] in ['"', "'"] and args[arg][0] == args[arg][-1]:
                args[arg] = args[arg][1:-1]
    return args


def check_regex(regex):
    """Check if a regex is valid. If not, it will catch and return False."""
    try:
        re.compile(regex)
    except re.error:
        raise IOError("Regex `" + regex + "` does not compile in Python.")


def check_error(child):
    """Raise an error for a problem with a child process."""
    if child.returncode != 0:
        output = (child.stdout + child.stderr).decode("utf-8")
        raise OSError("Problem encountered getting tshark JSON:" + output)


def filter_to_new_file(infile, dfilter):
    """Filter out packets not matching filter and save to a new file.
    This is useful for decreasing the time it takes to run this program."""
    child = sp.run(
        ["tshark", "-r", infile, "-Y", dfilter, "-w", TEMP_FILE],
        stdout=sp.PIPE,
        stderr=sp.PIPE,
    )
    check_error(child)


def get_pcap_bytes(pcap_file):
    """Get the raw bytes of a pcap file or stdin."""
    if pcap_file == "-":
        pcap_bytes = sys.stdin.buffer.read()
    else:
        with open(pcap_file, "rb") as f:
            pcap_bytes = f.read()
    return pcap_bytes


def get_pcap_json(pcap_file):
    """Get the jsonraw pcap json with tshark."""
    cmds = ["tshark", "-r", pcap_file, "-Tjsonraw"]
    child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.PIPE)
    check_error(child)
    json_text = child.stdout.decode("utf-8")
    return json.loads(json_text)


def get_replacements(pcap_json, fields, from_val, to_val):
    """Generate replacements given a field that exists."""
    replacements = {}
    num_packtes = len(pcap_json)
    for packet_num in range(num_packtes):
        packet = pcap_json[packet_num]
        results = []
        for field in fields:
            get_values(packet, field, results)
        if len(results) > 0:
            print("Replacing packet #" + str(packet_num))
            frame_raw = packet["_source"]["layers"]["frame_raw"][0]
            new_frame = alter_frame(frame_raw, results, from_val, to_val)
            replacements[frame_raw] = new_frame
    if len(replacements.keys()) == 0:
        print("[WARN] No packets altered!")
    return replacements


def alter_frame(frame_raw, results, from_val, to_val):
    """Make an actionable packet regex."""
    # It's possible that a field appears multiple times in a packet.
    # If this happens, then there will be multiple splices at different points.
    for result in results:
        if len(from_val) == 0 or re.search(from_val, result[0]):
            offset = result[1] * 2  # hex char count = 2x bytecount
            to_len = len(to_val)
            print("  Offset:" + str(offset))
            print("  Before:" + frame_raw[offset : offset + to_len])
            frame_raw = (
                frame_raw[:offset] + to_val + frame_raw[offset + to_len :]
            )
            print("  After:" + frame_raw[offset : offset + to_len])
    return frame_raw


def get_values(obj, target_key, result):
    """Inspired by https://stackoverflow.com/questions/33466450
    result is passed by reference, so adding to it can work recursively
    Iterate over the json so as to return all values for a given key"""
    if isinstance(obj, dict):
        for key in obj.keys():
            if key == target_key:
                result += [obj[key]]
            else:
                get_values(obj[key], target_key, result)
    elif isinstance(obj, list):
        for li_item in obj:
            get_values(li_item, target_key, result)


def replace_bytes(pcap_bytes, replacements):
    """Replace the bytes in the pcap using from/to in replacements as a guide."""
    for orig in replacements.keys():
        orig_bytes = bytes.fromhex(orig)
        replacement = replacements[orig]
        relpacement_bytes = bytes.fromhex(replacement)
        pcap_bytes = pcap_bytes.replace(orig_bytes, relpacement_bytes)
    return pcap_bytes


def write_file(outfile, pcap_bytes):
    """Write the results to the outfile."""
    if outfile == "-":  # Treat as stdout
        sys.stdout.buffer.write(pcap_bytes)
    else:
        with open(outfile, "wb") as f:
            f.write(pcap_bytes)


def cleanup():
    """Cleanup temporary file if one was created."""
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)


def main():
    """main()"""
    check_tshark()
    atexit.register(cleanup)
    args = get_args()

    infile = args["r"]
    outfile = args["w"]
    from_val = args["s"]
    to_val = args["d"]
    dfilter = args["Y"]
    # All fields with -Tjsonraw have _raw appended
    fields = [arg + "_raw" for arg in args["e"]]
    check_regex(from_val)

    if dfilter is not None:
        filter_to_new_file(infile, dfilter)
        infile = TEMP_FILE
    pcap_bytes = get_pcap_bytes(infile)
    pcap_json = get_pcap_json(infile)
    replacements = get_replacements(pcap_json, fields, from_val, to_val)
    new_pcap_bytes = replace_bytes(pcap_bytes, replacements)
    write_file(outfile, new_pcap_bytes)


if __name__ == "__main__":
    main()
