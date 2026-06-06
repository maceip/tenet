import re
from pathlib import Path

from setuptools import find_packages, setup

_version_src = Path(__file__).parent.joinpath("tenet", "packet", "__init__.py").read_text(encoding="utf-8")
VERSION = re.search(r'^VERSION\s*=\s*"([^"]+)"', _version_src, re.MULTILINE).group(1)

if __name__ == "__main__":

      setup(name='tenet',
            version=VERSION,
            description='tenet — an expert-routing mixnet (Sphinx packet format core).',
            author='George Danezis',
            author_email='g.danezis@ucl.ac.uk',
            url=r'http://sphinxmix.readthedocs.io/en/latest/',
            packages=find_packages(include=["tenet", "tenet.*"]),
            license="2-clause BSD",
            long_description="""tenet routes a question to the peer most likely to answer it well,
            over a Sphinx-format mixnet. The packet layer is a Python implementation of the
            Sphinx mix packet format.

            For full documentation see: http://sphinxmix.readthedocs.io/en/latest/
            """,

            setup_requires=['pytest-runner', "pytest"],
            tests_require=[
                  "pytest",
                  "future >= 0.14.3",
                  "pytest >= 3.0.0",
                  "msgpack-python >= 0.4.6",
                  "pynacl >= 1.1.0",
                  "aioquic >= 1.3.0",
                  "pqcrypto >= 0.4.0",
            ],
            install_requires=[
                  "future >= 0.14.3",
                  "pytest >= 3.0.0",
                  "msgpack-python >= 0.4.6",
                  "pynacl >= 1.1.0",
                  "aioquic >= 1.3.0",
                  "pqcrypto >= 0.4.0",
            ],
            entry_points={
                  "console_scripts": [
                        "tenet=tenet.edges.cli.main:main",
                        "tenet-relay=tenet.edges.cli.main:legacy_relay_main",
                        "tenet-expert=tenet.edges.cli.main:legacy_expert_main",
                        "tenet-client=tenet.edges.cli.main:legacy_client_main",
                        "tenet-directory=tenet.edges.cli.directory:main",
                  ],
            },
      )
