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
        exit(1)
    return old_excepthook(exceptionType, exception, traceback)


sys.excepthook = ensure_enviroment_excepthook
