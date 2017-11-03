# Monitoring-Systems-Version-Check
Checker script can fingerprint NagiosXI or Zabbix monitoring system. It's also trying to get a list of known CVE for this version
python 2.7 required
## Dependencies
bs4
```
pip install beautifulsoup4
```
## Usage
```
Usage: python2.7 checker.py [HOST] [PORT] [TYPE](optional)

Options :
-h, --help              Show help message and exit
-H, --host              Host you want to fingerprint
-p, --port              Port on which Monitoring System is located
-t, --type              Type of system. Use N for NagiosXI, Z for Zabbix. (If no parameter - Nagios by default)
```
