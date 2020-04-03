#!/usr/bin/env python3
"""Run tests against test files and then check their sha512 against expected
For the time being, skip parallelizing with pytest-xdist."""
import hashlib
import os
import subprocess as sp

import pytest


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
        scenarios = [
            [
                f_80211_ng,
                ["radiotap.datarate"],
                ".*",
                "aa",
                "6be03b6c5e185105c37411055867347a19f7f001101070ff93952f17ec0f94db00d379ed43c980a7dfcd868a8e656f63fd5f86ca2de4ded5e48cc8a9292ea98a",
            ],
            [
                f_eth,
                ["ip.src"],
                "01234567",
                ".*",
                "8d5ac5023b4cd4f603f7252f7a0a5740dc3b3d67787afcaaf9c10c52d363d510a1635b0fbe191fca5638141d0c7622a7c580352dafee1ee0a680b4ed74f2bf2e",
            ],
            [
                f_eth_ng,
                ["tcp.dstport"],
                ".*",
                "abcd",
                "e70ad99b83422ab84ea88c29b8629db802cd34d1bedf4ba24f2b80b108ad2fa6734b366be9336252bfd06ee048be04d49f19a2f41d99a60bea4687d6f7227464",
            ],
            [
                f_80211_ng,
                ["eth.dst"],
                ".*",
                "abcdef123456",
                "66a737eb51e335550eda3666af819c827030e254f4d7014219551faf5cfa2c765c7301c03365ad587edc35f279e07464231e1cbf0f4d992c8717df72e276c774",
            ],  # Expected noop
            [
                f_80211_ng,
                ["wlan.fc"],
                ".*",
                "a1b2",
                "66a737eb51e335550eda3666af819c827030e254f4d7014219551faf5cfa2c765c7301c03365ad587edc35f279e07464231e1cbf0f4d992c8717df72e276c774",
            ],
            [
                f_eth,
                ["tcp.srcport"],
                ".*",
                "ef01",
                "f182ef391a85a7176bd72d072dd39bcfa8a89ccd215559d24db177215c131868bfd576605d706ba41e8a039d8220d029f603ecd53f369a318a88ba7f32250f13",
            ],
            [
                f_eth_ng,
                ["ip6.dst"],
                ".*",
                "0123456789abcdef0123456789abcdef",
                "e70ad99b83422ab84ea88c29b8629db802cd34d1bedf4ba24f2b80b108ad2fa6734b366be9336252bfd06ee048be04d49f19a2f41d99a60bea4687d6f7227464",
            ],
            [
                f_eth,
                ["ip.src", "ip.dst"],
                "^(?:0a..|ac1.|c0a8).{4}",
                "00000000",
                "a5fcfae49e63be09ce5c1c48ec331f81443f9f3d66d459c3151eb66483e90da02ad905ee61dc6d3a9646f2c90a8939c8ed4c0e4f52b636681d1cebcc4e9b74e4",
            ],  # matches private IP addresses
        ]

        def add_scenario(scenario):
            """Add a scenario to the class list."""
            name_fields = " ".join(["-e " + sc for sc in scenario[1]])
            name = (
                "-r "
                + scenario[0]
                + " "
                + name_fields
                + " -s "
                + scenario[2]
                + " -d "
                + scenario[3]
            )
            fmtd_scenario = [
                name,
                {
                    "infile": "tests/files/" + scenario[0],
                    "fields": scenario[1],
                    "from_val": scenario[2],
                    "to_val": scenario[3],
                    "expd_sha512": scenario[4],
                },
            ]
            cls.scenarios.append(fmtd_scenario)

        for s in scenarios:
            add_scenario(s)

    def test_run(self, infile, fields, from_val, to_val, expd_sha512):
        """Run all scenarios. pytest_generate_tests targets this."""
        args = ["-r", infile, "-w", self.outfile, "-s", from_val, "-d", to_val]
        for field in fields:
            args += ["-e", field]
        sp.run(["python3", "src/regexcap.py"] + args)
        with open(self.outfile, "rb") as f:
            filebytes = f.read()
        filehash = hashlib.sha512(filebytes).hexdigest()
        if filehash != expd_sha512:
            pytest.fail(
                "Hash mismatch.\nExpected:"
                + expd_sha512
                + "\nActual:"
                + filehash
            )

    def teardown_class(self):
        """Cleanup temporary file if one was created."""
        if os.path.exists(self.outfile):
            os.remove(self.outfile)
