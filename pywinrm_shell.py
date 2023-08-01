#!/usr/bin/env python3
import sys
import subprocess
import platform
if platform.system().lower()=='windows':
        import pyreadline as readline 
else:
    import readline
import argparse
from colorama import Fore, Back, Style
from winrm.protocol import Protocol
from winrm.exceptions import WinRMTransportError

def args_get():
    debug = False
    args = argparse.ArgumentParser(description='PyWinRM Shell')
    username = args.add_argument('-u', '--username', help="Username to authenticate with.", default=None)
    password = args.add_argument('-p', '--password', help="Password to authenticate with.", default=None)
    ip_address = args.add_argument('-i', '--ip_address', help="Target host IP address.", default='127.0.0.1')
    port = args.add_argument('-P', '--port', help="Target host port.", type=int, default=5985)
    transport = args.add_argument('-t', '--transport', help="Transport protocol to use.", default='ntlm')
    cert_validation = args.add_argument('-c', '--cert_validation', help="Server certificate validation.", default='ignore')
    domain = args.add_argument('-d', '--domain', help="Domain to authenticate with.", default=None)
    #shell = args.add_argument('-s', '--shell', help="Shell to use.", default='powershell')
    https = args.add_argument('-https', '--enable-https', help="Enable HTTPS.", default=False)
    parsed_args = args.parse_args()
    if https == True:
        set_endpoint = str(f'https://{parsed_args.ip_address}:{parsed_args.port}/wsman')
    else:
        set_endpoint = str(f'http://{parsed_args.ip_address}:{parsed_args.port}/wsman')
    set_transport = str(parsed_args.transport)
    set_cert_validation = str(parsed_args.cert_validation)
    set_username = str(parsed_args.username)
    set_password = str(parsed_args.password)
    set_domain = str(parsed_args.domain)
    #set_shell = str(parsed_args.shell)

    if debug == True:
        print(f'[*] Parsed Arguments: {parsed_args}')
        print(f"[*] Endpoint: {set_endpoint}")
        print(f"[*] Transport: {set_transport}")
        print(f"[*] Server Certificate Validation: {set_cert_validation}")
        print(f"[*] Username: {set_username}")
        print(f"[*] Password: {set_password}")
        print(f"[*] Domain: {set_domain}")
        #print(f"[*] Shell: {set_shell}")

    try:
        p = Protocol(
            endpoint=set_endpoint,
            transport=set_transport,
            username=set_username,
            password=set_password,
            server_cert_validation=set_cert_validation)
        hostname = set_endpoint
    except Exception as e:
        print(f"[!] Error, {e}")
        sys.exit(1)
    
    return p, hostname

def host_check(hostname):
    print(f"[*] Checking if {hostname} is up...")
    param = '-n' if platform.system().lower()=='windows' else '-c'
    retcode = subprocess.call(['ping', param, '1', hostname], 
                              stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL)
    if retcode == 0:
        return True
    else:
        return False
    
def host_connect(p):
    try:
        shell_id = p.open_shell()
        return shell_id
    except:
        print(Fore.RED + "[!] Error, unable to connect to host." + Style.RESET_ALL)
        sys.exit()

def format_command(command):
    command = command.replace('\\', '\\\\')
    formatted_command = 'powershell -Command "' + command + '"'
    return formatted_command

def working_dir_get(p, shell_id):
    command_id = p.run_command(shell_id, format_command('Convert-Path .'))
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
    p.cleanup_command(shell_id, command_id)
    return std_out.decode('utf-8').strip()

def working_dir_set(current_dir):
    return str(current_dir)

def working_dir_change(p, shell_id, new_dir, current_dir):
    test_command = 'Test-Path -Path "' + new_dir + '"'
    command_id = p.run_command(shell_id, 'powershell -Command "' + test_command + '"')
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
    p.cleanup_command(shell_id, command_id)

    if std_out.decode('utf-8').strip().lower() == 'true':
        return str(new_dir)
    else:
        print(Fore.RED + f"[!] Error, {new_dir} does not exist." + Style.RESET_ALL)
        return str(current_dir)

def main():    
    p, hostname = args_get()
    directory_history = []

    if host_check(hostname) == False:
        force_connection = input(Fore.YELLOW + f"[?] Warning, Can't determine if {hostname} is up. Attempt to connect anyway? Default: N (Y/N) " + Style.RESET_ALL) 
        if not force_connection.lower().startswith('y'):
            print(Fore.RED + "[-] Aborting..." + Style.RESET_ALL)
            sys.exit()
        else:
            print(f"[*] Establishing connection to {hostname}...")
            shell_id = host_connect(p)
    else:
        print(f"[*] Establishing connection to {hostname}...")
        shell_id = host_connect(p)

    current_dir = str(working_dir_get(p, shell_id))
    while True:
        execute_on_host = False
        current_dir = working_dir_set(current_dir)
        display_current_dir = current_dir.replace("\\\\", "\\").replace("` ", " ").replace('"', '')
        display_current_dir = display_current_dir.replace("` ", " ")
        directory_history.append(current_dir)
        command = input(Fore.LIGHTYELLOW_EX + "PS " + Fore.CYAN + "PyWinRM> " + Style.RESET_ALL + display_current_dir + " ")
        readline.add_history(command)  # Add command to history
        
        if command.lower().startswith('cd '):
            if not command.lower().__contains__(':'):
                if command.lower().startswith('"'):
                    new_dir = str('\\'[-1:] + command[4:].strip('"'))
                else:
                    new_dir = str('\\'[-1:] + command[3:].strip('"'))
                
                current_dir = current_dir.replace('"', '')
                new_dir = str(current_dir.replace('`', "") + new_dir.replace('`', ""))
                new_dir= new_dir.replace("`", "` ")
                new_dir = new_dir.replace(' ', '` ')
                current_dir = working_dir_change(p, shell_id, new_dir, current_dir)
            else:
                new_dir = str('"' + command[3:].strip('') + '"')
                current_dir = working_dir_change(p, shell_id, new_dir, current_dir)
        
        elif command.lower() == 'cd' and len(command.lower()) <= 3:
            current_dir = str(directory_history[0])

        elif command.lower() == 'exit':
            confirm_exit = input(Fore.YELLOW + "[?] Are you sure you want to exit? (Press 'Y' to confirm)" + Style.RESET_ALL)
            if confirm_exit.lower() == 'y':
                p.cleanup_command(shell_id, command_id)
                p.close_shell(shell_id)
                sys.exit()
            else:
                continue

        elif command.lower().startswith('ls'):
            command = str('Get-ChildItem ' + '"' + current_dir + '"')
            command = format_command(command)
            execute_on_host = True

        elif command.lower().startswith('Get-Content'):
            if not command.lower().__contains__('-Path'):
                print(Fore.RED + "[!] Error, specify path to file. E.g. Get-Content -Path C:\\Users\\administrator\\Desktop\\example.txt" + Style.RESET_ALL)
                execute_on_host = False
            else:
                command = format_command(command)
                execute_on_host = True

        elif command.lower().startswith('cat '):
            command = str('Get-Content -Path ' + '"' + current_dir + '\\'[-1:] + command[4:]+ '"')
            command = format_command(command)
            execute_on_host = True

        elif command.lower().startswith('type '):
            command = str('Get-Content -Path ' + '"' + current_dir + '\\'[-1:] + command[5:] + '"')
            command = format_command(command)
            execute_on_host = True
        
        else:
            command = format_command(command)
            execute_on_host = True

        if execute_on_host == True:
            try:
                command_id = p.run_command(shell_id, command)
                std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
                for line in std_out.decode('utf-8').splitlines():
                    print(f'{line}')
                execute_on_host = False
            except WinRMTransportError as e:
                print(Fore.RED + f'[!] {e}' + Style.RESET_ALL)
                try:
                    print("[*] Reconnecting...")
                    shell_id = host_connect(p)  # Attempt to reconnect by opening a new shell
                    command_id = p.run_command(shell_id, command)
                    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
                    for line in std_out.decode('utf-8').splitlines():
                        print(f'{line}')
                    execute_on_host = False
                except:
                    print(Fore.RED + "[!] Error, connection lost." + Style.RESET_ALL)
                    sys.exit()

            std_err_out = std_err.decode('utf-8').splitlines()
            for line in std_err_out:
                print(Fore.RED, line, Style.RESET_ALL)

if __name__ == "__main__":
    main()