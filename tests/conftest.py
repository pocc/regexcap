#!/usr/bin/env python3
"""Functions that pytest will look for and run automatically."""


def pytest_generate_tests(metafunc):
    """Taken from pytest documentation to generate table tests:
    https://docs.pytest.org/en/latest/example/parametrize.html#paramexamples
    Test classes MUST have a scenarios attribute or this will error."""
    metafunc.cls.setup_class()
    idlist = []
    argvalues = []
    argnames = []
    for scenario in metafunc.cls.scenarios:
        idlist.append(scenario[0])
        items = scenario[1].items()
        argnames = [x[0] for x in items]
        argvalues.append([x[1] for x in items])
    metafunc.parametrize(argnames, argvalues, ids=idlist, scope="class")
