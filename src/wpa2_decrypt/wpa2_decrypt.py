#!/usr/bin/env python3
"""Decrypt WPA2 captures in place"""
import shutil
import subprocess as sp


def get_src(filename, frames):
    cmds = (
        "tshark -r " + filename + " -Y data -Tfields -e frame.number -e data"
    ).split(" ")
    child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.PIPE)
    text_lines = child.stdout.decode("utf-8").split("\n")
    text_lines = list(filter(None, text_lines))
    for line in text_lines:
        frame_num, data = line.split("\t")
        # Only add src data if there is already decrypted dst data
        # -e data can pick up other undesired fields
        if frame_num in frames:
            if "TCP" in data:
                print(data)
            frames[frame_num]["src"] = data
    return frames


def get_packet_from_hex(hex_text):
    packet = ""
    reading_decrypted_lines = False
    for line in hex_text.split("\n"):
        if line.startswith("Decrypted CCMP data"):
            reading_decrypted_lines = True
        # If there is another reconstituted section, skip it
        elif line[0] not in "abcdef0123456789":
            reading_decrypted_lines = False
        if reading_decrypted_lines and line[0] != "D":
            packet += line[6:53].replace(" ", "")
    return packet


def get_dst(filename):
    frames = {}
    cmds = (
        "tshark -r "
        + filename
        + ' -o wlan.enable_decryption:TRUE -o uat:80211_keys:"wpa-pwd","Cisco123Cisco123:TEST1" -x'
    ).split(" ")
    child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.PIPE)
    print(child.stderr.decode("utf-8"))
    hex_packet_list = child.stdout.decode("utf-8").split("\n\n")
    hex_packet_list = list(filter(None, hex_packet_list))

    for i in range(len(hex_packet_list)):
        packet = hex_packet_list[i]
        packet_bytes = get_packet_from_hex(packet)
        if len(packet_bytes) > 0:
            if str(i + 1) not in frames:
                frames[str(i + 1)] = {}
            frames[str(i + 1)]["dst"] = packet_bytes
    return frames


frame_maps = get_dst("shortwpa.pcapng")
updated_frame_maps = get_src("shortwpa.pcapng", frame_maps)
shutil.copy2("shortwpa.pcapng", "decrypted.pcapng")

frame_num = "133"
print("Decrypting frame number", frame_num)
src = updated_frame_maps[frame_num]["src"]
dst = updated_frame_maps[frame_num]["dst"]
cmds = [
    "regexcap",
    "-Y",
    "frame.number==" + frame_num,
    "-r",
    "decrypted.pcapng",
    "-w",
    "decrypted.pcapng",
    "-e",
    "data",
    "-s",
    src,
    "-d",
    dst,
]
sp.run(cmds)
# sp.run(['tshark', '-r', 'decrypted.pcap', '-w', 'decrypted.pcapng'])
# cmds = ["regexcap", "-Y", "wlan.ccmp.extiv", "-r", "decrypted.pcapng", "-w", "decrypted.pcapng", "-e", "wlan.ccmp.extiv"]
# sp.run(cmds)
