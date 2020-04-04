#!/usr/bin/env python3
"""Run tests against test files and then check their sha512 against expected
For the time being, skip parallelizing with pytest-xdist."""
import hashlib
import os
import subprocess as sp

import pytest

# hashes for scenarios below (10)
hashes = [
    "6be03b6c5e185105c37411055867347a19f7f001101070ff93952f17ec0f94db00d379ed43c980a7dfcd868a8e656f63fd5f86ca2de4ded5e48cc8a9292ea98a",
    "8d5ac5023b4cd4f603f7252f7a0a5740dc3b3d67787afcaaf9c10c52d363d510a1635b0fbe191fca5638141d0c7622a7c580352dafee1ee0a680b4ed74f2bf2e",
    "e70ad99b83422ab84ea88c29b8629db802cd34d1bedf4ba24f2b80b108ad2fa6734b366be9336252bfd06ee048be04d49f19a2f41d99a60bea4687d6f7227464",
    "66a737eb51e335550eda3666af819c827030e254f4d7014219551faf5cfa2c765c7301c03365ad587edc35f279e07464231e1cbf0f4d992c8717df72e276c774",
    "66a737eb51e335550eda3666af819c827030e254f4d7014219551faf5cfa2c765c7301c03365ad587edc35f279e07464231e1cbf0f4d992c8717df72e276c774",
    "f182ef391a85a7176bd72d072dd39bcfa8a89ccd215559d24db177215c131868bfd576605d706ba41e8a039d8220d029f603ecd53f369a318a88ba7f32250f13",
    "e70ad99b83422ab84ea88c29b8629db802cd34d1bedf4ba24f2b80b108ad2fa6734b366be9336252bfd06ee048be04d49f19a2f41d99a60bea4687d6f7227464",
    "a5fcfae49e63be09ce5c1c48ec331f81443f9f3d66d459c3151eb66483e90da02ad905ee61dc6d3a9646f2c90a8939c8ed4c0e4f52b636681d1cebcc4e9b74e4",
    "ecf7e1b3831d5d26a14e7940205efe34309663e507fdb596bb9ba000fc5d5c96ae5eec3d93c7561a42fcd27cfc67378aebdb0eea8195f4b4c2e70a3f238707d8",
    "fa589b8a68487f803765b81fb55a4ff321d32c31174a0ef211ae685f3ba8d93a2c5f64ba552fb6862852a1067ebf4bc20c58465b4b4e3100cebaefedaffa1e97",
]


class TestSwitches:
    """Test multiple switches."""

    @classmethod
    def setup_class(cls):
        """Setup functions."""
        f_80211_ng = "80211_2pkts.pcapng"
        f_eth = "eth_ip_2pkts.pcap"
        f_eth_ng = "eth_ip6_2pkts.pcapng"

        cls.outfile = "pytest.pcap"
        cls.scenarios = list()
        rfc1918_regex = "^(?:0a..|ac1.|c0a8).{4}"
        bogus_ip6_addr = "0123456789abcdef0123456789abcdef"
        scenarios = [
            [f_80211_ng, ["radiotap.datarate"], ".*", "aa", [], hashes[0]],
            [f_eth, ["ip.src"], "01234567", ".*", [], hashes[1]],
            [f_eth_ng, ["tcp.dstport"], ".*", "abcd", [], hashes[2]],
            # Expected noop
            [f_80211_ng, ["eth.dst"], ".*", "abcdef123456", [], hashes[3]],
            [f_80211_ng, ["wlan.fc"], ".*", "a1b2", [], hashes[4]],
            [f_eth, ["tcp.srcport"], ".*", "ef01", [], hashes[5]],
            [f_eth_ng, ["ip6.dst"], ".*", bogus_ip6_addr, [], hashes[6]],
            # matches private IP addresses
            [f_eth, ["ip.src", "ip.dst"], rfc1918_regex, "00000000", [], hashes[7]],
            # scapy test
            [f_eth_ng, ["ip6.dst"], ".*", bogus_ip6_addr, ["-p"], hashes[8]],
            # multiprocessing test
            [f_eth, ["tcp.srcport"], ".*", "ef01", ["-m"], hashes[9]],
        ]

        def add_scenario(scen):
            """Add a scenario to the class list."""
            fields = " ".join(["-e " + sc for sc in scen[1]])
            extra_args = ""
            if len(scen[4]) > 0:
                extra_args = " " + "".join(scen[4])
            name_parts = [scen[0], fields, scen[2], scen[3], extra_args, cls.outfile]
            name = "-r {} -s {} -d {}{} -w {}".format(*name_parts)
            fmtd_scenario = [
                name,
                {
                    "infile": "tests/files/" + scen[0],
                    "fields": scen[1],
                    "from_val": scen[2],
                    "to_val": scen[3],
                    "addtnl_args": scen[4],
                    "expd_sha512": scen[5],
                },
            ]
            cls.scenarios.append(fmtd_scenario)

        for s in scenarios:
            add_scenario(s)

    def test_run(self, infile, fields, from_val, to_val, addtnl_args, expd_sha512):
        """Run all scenarios. pytest_generate_tests targets this."""
        args = ["-r", infile, "-w", self.outfile, "-s", from_val, "-d", to_val]
        args += addtnl_args
        for field in fields:
            args += ["-e", field]
        sp.run(["python3", "src/regexcap.py"] + args)
        with open(self.outfile, "rb") as f:
            filebytes = f.read()
        filehash = hashlib.sha512(filebytes).hexdigest()
        if filehash != expd_sha512:
            pytest.fail(
                "Hash mismatch.\nExpected:" + expd_sha512 + "\nActual:" + filehash
            )

    def teardown_class(self):
        """Cleanup temporary file if one was created."""
        if os.path.exists(self.outfile):
            os.remove(self.outfile)
