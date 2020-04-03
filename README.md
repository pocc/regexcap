# RegexCap

Replace packet fields with a regex and display filter.
This is useful for removing personally sensitive information by field.
[TraceWrangler](https://www.tracewrangler.com/), a windows GUI tool, also performs this function.

## Usage

## Example Usage

### Example 1: Replace MAC address NIC bytes

For example to replace the NIC-specific part of all mac addresses:

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
$ regexcap -r old.pcap -w new.pcap -d '^(?:0a..|ac1.|c0a8).{4}' -s '00000000'
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

## Usage Notes

* Currently set to error if there is a length mismatch between old and new values.

## License

Apache 2.0
