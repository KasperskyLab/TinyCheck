#!/usr/bin/python
import os
import subprocess
import platform
import socket
import pkg_resources
import psutil

__author__ = 'Eugeny N Ablesov'
__version__ = '1.0.17'

def collect_accounts_info():
    """ This call collects generic information about
        user accounts presented on system running TinyCheck.

        No personal information collected or provided by this call.
    """
    accs = { }
    users = psutil.users()
    for user in users:
        accs[user.name + '@' + user.host] = {
            'started': user.started,
            'term': user.terminal
    }
    alt_user = os.getenv('SUDO_USER', os.getenv('USER'))
    usr = 'root' if os.path.expanduser('~') == '/root' else alt_user
    pid = psutil.Process().pid
    term = psutil.Process().terminal() if 'Linux' in platform.system() else 'win'
    accs[usr + '@' + term] = { 'pid': pid }
    return accs

def collect_os_info():
    """ This call collects generic information about 
        operating system running TinyCheck.

        No personal information collected or provided by this call.
    """
    os_info = { }
    os_info['system'] = platform.system()
    os_info['release'] = platform.release()
    os_info['version'] = platform.version()
    os_info['platform'] = platform.platform(aliased=True)
    if 'Windows' in os_info['system']:
        os_info['dist'] = platform.win32_ver()
    if 'Linux' in os_info['system']:
        os_info['dist'] = platform.libc_ver()
    return os_info

def collect_hardware_info():
    """ This call collects information about hardware running TinyCheck.

        No personal information collected or provided by this call.
    """
    hw_info = { }
    hw_info['arch'] = platform.architecture()
    hw_info['machine'] = platform.machine()
    hw_info['cpus'] = psutil.cpu_count(logical=False)
    hw_info['cores'] = psutil.cpu_count()
    hw_info['load'] = psutil.getloadavg()
    disk_info = psutil.disk_usage('/')
    hw_info['disk'] = {
        'total': disk_info.total,
        'used': disk_info.used,
        'free': disk_info.free
    }
    return hw_info

def collect_network_info():
    """ This call collects information about 
        network configuration and state running TinyCheck.

        No personal information collected or provided by this call.
    """
    net_info = { }
    net_info['namei'] = socket.if_nameindex()
    addrs = psutil.net_if_addrs()
    state = psutil.net_io_counters(pernic=True)
    for interface in addrs.keys():
        net_info[interface] = { }
        int_info = state[interface]
        props = [p for p in dir(int_info)
            if  not p.startswith("_")
                and not p == "index"
                and not p == "count"]
        for prop in props:
            net_info[interface][prop] = getattr(int_info, prop)
    return net_info

def collect_dependency_info(package_list):
    """ This call collects information about
        python packages required to run TinyCheck.
    
        No personal information collected or provided by this call.
    """
    dependencies = { }
    installed_packages = list(pkg_resources.working_set)
    installed_packages_list = sorted(["%s==%s"
        % (installed.key, installed.version)
        for installed in installed_packages])
    for pkg in installed_packages_list:
        [package_name, package_version] = pkg.split('==')
        if package_name in package_list:
            dependencies[package_name] = package_version
    return dependencies

def collect_db_tables_records_count(db_path, tables):
    result = { }
    for table in tables:
        query = 'SELECT COUNT(*) FROM %s' % (table)
        sqlite_call = subprocess.Popen(['sqlite3', db_path, query], stdout = subprocess.PIPE)
        stout, sterr = sqlite_call.communicate()
        val = stout.decode("utf-8")
        recs = int(val) if val else 0
        result[table] = recs
    return result

def collect_internal_state(db_path, tables, to_check):
    """ This call collects information about
        installed TinyCheck instance and its internal state.
    
        No personal information collected or provided by this call.
    """
    state_ = { }
    available = os.path.isfile(db_path)
    dbsize = 0
    state_['db'] = {
        'available': available,
        'size': dbsize
    }
    state_['db']['records'] = { }
    if available:
        state_['db']['size'] = os.stat(db_path).st_size
        state_['db']['records'] = collect_db_tables_records_count(db_path, tables)

    services_ = { }
    for alias in to_check:
        status = subprocess.call(['systemctl', 'is-active', '--quiet', '%s' % (to_check[alias])])
        state = ''
        if status != 0:
            sysctl_call = subprocess.Popen(
                ["systemctl", "status", "%s" % (to_check[alias]),
                r"|",
                "grep",
                r"''"],
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE)
            stout, sterr = sysctl_call.communicate()
            state = stout.decode("utf-8")
            errs = sterr.decode("utf-8")
            if "could not be found" in errs:
                state = 'Service not found'
        services_[alias] = {
            'running': status == 0,
            'status': status,
            'state': state
        }
    state_['svc'] = services_
    return state_

def main():
    print("TinyCheck diagnostics script.\nVersion: %s" % (__version__))
    print("")

    db_path = '/usr/share/tinycheck/tinycheck.sqlite3'
    tables = ['iocs', 'whitelist', 'misp']
    services = { }
    services['frontend'] = 'tinycheck-frontend.service'
    services['backend'] = 'tinycheck-backend.service'
    services['kiosk'] = 'tinycheck-kiosk.service'
    services['watchers'] = 'tinycheck-watchers.service'

    deps = [
        'pymisp', 'sqlalchemy', 'ipwhois',
        'netaddr', 'flask', 'flask_httpauth',
        'pyjwt', 'psutil', 'pydig', 'pyudev',
        'pyyaml', 'wifi', 'qrcode', 'netifaces',
        'weasyprint', 'python-whois', 'six' ]

    diagnostics = { }
    diagnostics['acc'] = collect_accounts_info()
    diagnostics['os'] = collect_os_info()
    diagnostics['hw'] = collect_hardware_info()
    diagnostics['net'] = collect_network_info()
    diagnostics['deps'] = collect_dependency_info(deps)
    diagnostics['state'] = collect_internal_state(db_path, tables, services)
    report = { 'diagnostics': diagnostics }
    print(report)
    print("")

if __name__ == '__main__':
    main()
