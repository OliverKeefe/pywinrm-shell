# PyWinRM-Shell

A simple WinRM shell for penetration testers implemented using the PyWinRM module [PyWinRM](https://pypi.org/project/pywinrm/).

Windows Remote Management (WinRM) is the Microsoft implementation of the WS-Management protocol, which is a standard SOAP-based (Simple Object Access Protocol), firewall-friendly protocol that allows interoperation between hardware and operating systems from different vendors. It's intended for SysAdmins for the purposes of automation, however, like with most things it can be abused.

## Installation 
```shell
git clone https://github.com/OliverKeefe/pywinrm-shell.git && cd pywinrm-shell && pip install -r requirements.txt 
```

## Example usage
```shell
python3 sneky_winrm.py -u 'username' -p 'Sup3r_53cret_p@ssw0rd!' -i '172.168.66.53' -t 'ntlm' -P 5985 -https False
```

