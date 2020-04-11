# RegexCap

Replace packet fields with a regex and display filter.
This is useful for removing personally sensitive information by field.
[TraceWrangler](https://www.tracewrangler.com/) also performs this function,
but is limited to a Windows GUI and has a limited set of editable fields.

## Installation

You can install from [regexcap@PyPI](https://pypi.org/project/RegexCap/0.0/) with pip.

```bash
pip install regexcap
```

Alternatively, you can install by cloning it and installing it with pip.

```
git clone https://github.com/pocc/regexcap
cd regexcap
pip install .
```

## Command Line Options

```bash
$ regexcap --help
usage: regexcap [-h] -r R -w W -e E [-s S] -d D [-Y Y] [-m] [-p]

Replace pcap fields with regex

optional arguments:
  -h, --help  show this help message and exit
  -r R        input file. Use - for stdin
  -w W        output file. Use - for stdout
  -e E        field to change. Multiple fields can be specified like `-e ip.src -e ip.dst`. Replacements will occur on all specified fields. If `frame` is specified, matching frameswill be replaced in their entirety.
  -s S        source field bytes regex. Defaults to regex ".*" if no arg is provided.
  -d D        destination field bytes
  -Y Y        Before replacing bytes, delete packets that do not match this display filter
  -m          Speed up execution with multiprocessing by using one process per cpu.Output is always pcapng. If source file is a pcapng, then header data will be rewritten recognizing mergecap as the most recent packet writer.
  -p          Use scapy for packet processing. Currently 50% slower and always saves to pcap.
```

## Usage notes

* This replaces bytes in packets, not in packet or pcap headers. Those fields are not accessible to tshark.
* This replaces hexademical bytes like byte '\x2a' = ASCII '*'. To replace with ASCII, use `-A`.
* Options `-r`, `-w`, `-e`, and `-Y` are copied from tshark for sake of familiarity
* Whil the default is to not modify pcap/packet header data, multiprocessing (`-m`) modifies and
  scapy-processing (`-p`) drops this data.
* `-m` uses multiprocessing and will speed up execution for large files
* `-Y` and `-m` create temporary files that are deleted on exit
* Avoid shorthand display filters like `-e ip.addr` and use their more explicit
  representations like `-e ip.src -e ip.dst`. Tshark maps shorthand
  display filters to exactly one field in json output, so fewer fields may be
  replaced than expected.
* Currently set to error if there is a length mismatch between old and new values.
* This program will be slow! It uses python with a naive algorithm (i.e. it works)

## Example Usage

### Example 1: Replace MAC address NIC bytes

For example to replace the NIC-specific (last 6 bytes) part of all mac addresses:

```bash
$ tshark -r new.pcap -c 1
    1 6c:96:cf:d8:7f:e7 → cc:65:ad:da:39:70 108.233.248.45 → 157.245.238.3 ...
$ regexcap -r old.pcap -w new.pcap -e eth.src -e eth.dst -s '.{6}$' -d 000000
$ tshark -r new.pcap -c 1
    1 6c:96:cf:00:00:00 → cc:65:ad:00:00:00 108.233.248.45 → 157.245.238.3 ...
```

* `.{6}`: Take exactly six bytes of any type
* `$`: This regex ends at the end of the field

### Example 2: Replace private IP addresses

To replace all private IP addresses with quad 0's, use a byte regex like so:

```bash
$ tshark -r new.pcap -c 1
    1   0.000000 192.168.1.246 → 217.221.186.35 TCP  54 59793 → https(443) [ACK] Seq=1 Ack=1 Win=2048 Len=0
$ regexcap -r old.pcap -w new.pcap -d '^(?:0a..|ac1.|c0a8).{4}' -s '00000000' -e ip.addr
$ tshark -r new.pcap -c 1
    1   0.000000      0.0.0.0 → 217.221.186.35 TCP  54 59793 → https(443) [ACK] Seq=1 Ack=1 Win=2048 Len=0
```

Breaking down the regex, an IP address is 32 bits => 8 nibbles (hexadecimal characters).
The network bits of each of the private subnets determines how many nibbles each requires.
In other words /8 => 2 network chars, /12 => 3 network chars, /16 => 4 network chars.

* `^`: regex starts at beginning of field
* `(?:`...`)`:
* `10.0.0.0/8 =====> 0x0a + ......`
* `172.16.0.0/12 ==> 0xac1 + .....`
* `192.168.0.0/16 => 0xc0a8 + ....`
* `.{4}` summarizes the last 4 nibbles that are shared

To convert any IP address octet from decimal to hex, you can use the python built-in:

```python
>>> hex(172)
'0xac'
```

## Testing

Run `tests/run_tests` or `pytest -vvv -x` from the root dir.

## License

Apache 2.0


## Contact

Ross Jacobs, author, rj\[AT\]swit.sh
https://github.com/pocc/regexcap
