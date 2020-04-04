#!/usr/bin/env python3
"""
  Ross Jacobs, 2020, tshark.dev
  This script, provided the SSID and secret, will replace
  encrypted data bytes with the unencrypted data bytes.
  After completion, it should print the number of packets modified

  WARNING: This program will be slow! It uses python with a naive algorithm.
"""
import argparse as ap
import atexit
import json
import math
import multiprocessing
import os
import re
import shutil
import subprocess as sp
import sys
import time


TEMP_FOLDER = "temp_regexcap"
TEMP_FILE = ".temp.pcapng"


def check_tshark():
    """Check whether tshark can be used."""
    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        raise OSError("Unable to find tshark. Check your PATH & installation.")


def get_args():
    """Get the args with argparse."""
    desc = "Replace pcap fields with regex"
    fcls = ap.RawTextHelpFormatter
    parser = ap.ArgumentParser(prog="regexcap", description=desc, formatter_class=fcls)
    # Grab examples from README and post into epilog
    with open("README.md") as f:
        regex = re.compile(r"(## Usage notes[\s\S]*)## Testing")
        readme_usage = re.findall(regex, f.read())[0]
    parser.epilog = readme_usage

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
        "-m": "Speed up execution with multiprocessing by using one process per cpu."
        "Output is always pcapng. If source file is a pcapng, then header data "
        "will be rewritten recognizing mergecap as the most recent packet writer.",
        "-p": "Use scapy for packet processing. Currently 50% slower and always saves to pcap.",
    }

    parser.add_argument("-r", action="store", help=_help["-r"], required=True)
    parser.add_argument("-w", action="store", help=_help["-w"], required=True)
    parser.add_argument("-e", action="append", help=_help["-e"], required=True)
    parser.add_argument("-s", action="store", help=_help["-s"], default=".*")
    parser.add_argument("-d", action="store", help=_help["-d"], required=True)
    parser.add_argument("-Y", action="store", help=_help["-Y"])
    parser.add_argument("-m", action="store_true", help=_help["-m"])
    parser.add_argument("-p", action="store_true", help=_help["-p"])
    args = vars(parser.parse_args())
    # Verify regex in -s is valid
    check_regex(args["s"])
    # Remove encapsulating single/double quotes around any argument
    for arg in args:
        if isinstance(args[arg], str) and len(args[arg]) > 2:
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
    cmds = ["tshark", "-r", infile, "-Y", dfilter, "-w", TEMP_FILE]
    child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.PIPE)
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
            frame_raw = frame_raw[:offset] + to_val + frame_raw[offset + to_len :]
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


def replace_bytes_over_packets(infile, outfile, replacements):
    """Replace the bytes for each packet using scapy."""
    try:
        import scapy.all as scapyall
    except ImportError:
        err_msg = "-p requires scapy to be installed (pip install scapy)"
        raise ImportError(err_msg)
    packets = scapyall.rdpcap(infile)
    mod_packets = []
    for packet in packets:
        pcap_bytes = bytes(packet)
        for orig in replacements.keys():
            orig_bytes = bytes.fromhex(orig)
            replacement = replacements[orig]
            relpacement_bytes = bytes.fromhex(replacement)
            pcap_bytes = pcap_bytes.replace(orig_bytes, relpacement_bytes)
        mod_packets.append(pcap_bytes)

    if outfile == "-":  # Treat as stdout
        scapyall.wrpcap(TEMP_FILE, packets)
        with open(TEMP_FILE, "rb") as f:
            file_bytes = f.read()
            sys.stdout.buffer.write(file_bytes)
    else:
        scapyall.wrpcap(outfile, packets)


def replace_bytes_over_file(infile, outfile, replacements):
    """Replace the bytes in the pcap using from/to in replacements as a guide."""
    pcap_bytes = get_pcap_bytes(infile)
    for orig in replacements.keys():
        orig_bytes = bytes.fromhex(orig)
        replacement = replacements[orig]
        relpacement_bytes = bytes.fromhex(replacement)
        pcap_bytes = pcap_bytes.replace(orig_bytes, relpacement_bytes)

    write_file(outfile, pcap_bytes)


def get_num_packets(pcap_file):
    """Get the number of packets in a packet capture."""
    cmds = ["capinfos", "-cM", pcap_file]
    child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.DEVNULL)
    if child.returncode != 0:
        error_msg = "File `" + pcap_file + "`is not a packet capture!"
        raise FileNotFoundError(error_msg)
    output = child.stdout.decode("utf-8")
    num_ptks = int(re.search(r"(\d+)\n$", output)[1])
    return num_ptks


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
    if os.path.exists(TEMP_FOLDER):
        shutil.rmtree(TEMP_FOLDER)


def log_str(proc_str, start):
    """Create a preamble string for stdout."""
    former = "[{:>4}".format(proc_str)
    latter = "] {:.2f}".format(round(time.time() - start, 3))
    return former + latter


def run(proc_num, infile, outfile, fields, from_val, to_val, use_scapy, start):
    """Run with the arguments"""
    proc = str(proc_num)
    print(log_str(proc, start), ": Starting")
    pcap_json = get_pcap_json(infile)
    print(log_str(proc, start), ": Received pcap json from tshark")
    replacements = get_replacements(pcap_json, fields, from_val, to_val)
    if len(replacements.keys()) == 0:
        print(log_str(proc, start), ": No packets altered!")
    print(log_str(proc, start), ": Generated byte replacements")
    # Use scapy to replace bytes per packet or for the whole file (much slower)
    if use_scapy:
        replace_bytes_over_packets(infile, outfile, replacements)
    else:
        replace_bytes_over_file(infile, outfile, replacements)
    print(log_str(proc, start), ": Saved file")


def main():
    """main()"""
    check_tshark()
    atexit.register(cleanup)
    start = time.time()
    os.makedirs(TEMP_FOLDER, exist_ok=True)
    args = get_args()

    # Explicitly naming these variables for clarity
    infile = args["r"]
    outfile = args["w"]
    from_val = args["s"]
    to_val = args["d"]
    dfilter = args["Y"]
    use_scapy = args["p"]
    use_multiprocessing = args["m"]
    fields = [arg + "_raw" for arg in args["e"]]

    if dfilter:
        filter_to_new_file(infile, dfilter)
        infile = TEMP_FILE
    if not use_multiprocessing:
        run(0, infile, outfile, fields, from_val, to_val, use_scapy, start)
    else:
        # Splitting with editcap is FAST, so use that to buffer
        num_packets = get_num_packets(infile)
        buffer_num = math.ceil(num_packets / multiprocessing.cpu_count())
        # Create partial pcaps with every 100 packets
        editcap_out = TEMP_FOLDER + "/.partial.pcap"
        cmds = ["editcap", infile, editcap_out, "-c", str(buffer_num)]
        child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.PIPE)
        check_error(child)
        partial_names = os.listdir(TEMP_FOLDER)
        partial_files = [TEMP_FOLDER + "/" + f for f in partial_names]
        args = [fields, from_val, to_val, use_scapy, start]
        pool = multiprocessing.Pool(multiprocessing.cpu_count())
        work_set = []
        for i in range(len(partial_files)):
            partial = partial_files[i]
            work_set.append([i, partial, partial, *args])
        pool.starmap(run, work_set)

        cmds = ["mergecap", "-w", outfile] + partial_files
        child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.PIPE)
        check_error(child)
        print("Finished in " + str(time.time() - start) + " seconds.")


if __name__ == "__main__":
    main()
