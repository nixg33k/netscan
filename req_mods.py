import sys

old_excepthook = sys.excepthook


def ensure_enviroment_excepthook(exceptionType, exception, traceback):
    required = {'socket', 'time', 'os', 'netifaces', 'netaddr', 'nmap', 'pprint', 're', 'subprocess', 'logging',
                'argparse', 'resource', 'pkg_resources', 'netaddr', 'portscan', 'fluffy'}

    if exceptionType == ModuleNotFoundError or exceptionType == ImportError:
        print('This script can only be run if all below Python modules are installed.')
        print("Please install the following Python Modules")
        # print('This script can only be run if all modules are installed : {0}'.format(exception.msg), file=sys.stderr)
        print(*required, sep=", ")
        print("\n\n Note: Some modules may already be part of Python3 \n and cannot be installed with pip.\n Please take note.")
        print("For Python 3.8 in Ubuntu 20.04 recent update, only the following needed to installed.")
        print("pip install netaddr resource argparse netifaces nmap portscan")
        exit(1)
    return old_excepthook(exceptionType, exception, traceback)


sys.excepthook = ensure_enviroment_excepthook
