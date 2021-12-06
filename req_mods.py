import sys

old_excepthook = sys.excepthook


def ensure_enviroment_excepthook(exceptionType, exception, traceback):
    required = {'socket', 'time', 'os', 'netifaces', 'netaddr', 'python-nmap', 'pprint', 're', 'subprocess', 'logging',
                'argparse', 'resource', 'pkg_resources', 'netaddr', 'portscan', 'distro'}

    if exceptionType == ModuleNotFoundError or exceptionType == ImportError:
        print('This script can only be run if all below Python modules are installed.')
        print("Please install the following Python Modules")
        # print('This script can only be run if all modules are installed : {0}'.format(exception.msg), file=sys.stderr)
        print(*required, sep=", ")
        print("\n\n Note: Some modules may already be part of Python3 and cannot be installed with pip.\n Please take note.")
        print("For Python 3.5+ in Ubuntu 20.04 recent update, only the following needed to installed.")
        print("pip install netaddr netifaces python-nmap portscan distro")
        print("\nAlso you must install the nmap OS package.")
        exit(1)
    return old_excepthook(exceptionType, exception, traceback)


sys.excepthook = ensure_enviroment_excepthook
