import subprocess as sp

filename = "telnet-raw.pcap"


def get_telnet_frames(fname, telnet_data) -> [int]:
    """Gets frames that match a telnet prompt like '$' or 'Password:'
    Return frames that send input to the server until a newline (\r or \n) is sent."""
    cmds = [
        "tshark",
        "-r",
        fname,
        "-Y",
        "telnet.data==" + telnet_data,
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]

    child = sp.run(cmds, stdout=sp.PIPE, stderr=sp.PIPE)
    if child.returncode != 0:
        raise OSError("Problem with running tshark:", child.stdout, child.stderr)
    output = child.stdout.decode("utf-8")
    frame_nums = output.strip().split("\n")

    matching_frames = []
    for i in range(len(frame_nums)):
        initial_frame = frame_nums[i]
        # Make sure that we're captuing the side of the telnet conversation that's being prompted
        child = sp.run(
            [
                "tshark",
                "-r",
                fname,
                "-Y",
                "frame.number==" + initial_frame,
                "-T",
                "fields",
                "-e",
                "ip.src",
            ],
            stdout=sp.PIPE,
            stderr=sp.PIPE,
        )
        if child.returncode != 0:
            raise OSError("Problem with running tshark:", child.stdout, child.stderr)
        server_ip = child.stdout.decode("utf-8")
        dfilter = (
            "ip.src!=" + server_ip + "&&frame.number>" + initial_frame + "&&telnet"
        )
        cmds = [
            "tshark",
            "-r",
            fname,
            "-Y",
            dfilter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "telnet.data",
        ]
        frame_data = sp.check_output(cmds).decode("utf-8").strip().split("\n")
        for frame in frame_data:
            frame_num, data = frame.split("\t")
            if "\\n" in data or "\\r" in data:
                break
            else:
                matching_frames.append(int(frame_num))
    return matching_frames


password_frames = get_telnet_frames(filename, "$")
print("Found matching password frames:", password_frames)
frame_filter = "||".join(["frame.number==" + str(i) for i in password_frames])
last_child = sp.run(
    [
        "regexcap",
        "-r",
        filename,
        "-w",
        "fixed.pcap",
        "-Y",
        frame_filter,
        "-e",
        "telnet.data",
        "-s",
        "^.{2}$",
        "-d",
        "2a",
    ],
    stdout=sp.PIPE,
    stderr=sp.PIPE,
)
print(last_child.stdout.decode("utf-8"))
