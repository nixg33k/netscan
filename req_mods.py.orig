import sys


def ensure_enviroment():
    try:
        import argparse
        import importlib.util
        import logging
        import netaddr
        import netifaces
        import nmap
        import os
        import pprint
        import re
        import resource
        import socket
        import subprocess
        import sys
        import time
    except ModuleNotFoundError or ImportError as ee:
        print('This script can only be run if the modules are installed : {0}'.format(ee.msg), file=sys.stderr)
        exit(13)


ensure_enviroment()
