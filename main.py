import sys, subprocess, re
from urllib.request import urlopen
from urllib.error import HTTPError


class Trace:
    def __init__(self, dst):
        self.dst = dst

    def run(self):
        print(f'Tracing route to {self.dst}, 30 hops max')
        process = subprocess.Popen(['tracert', self.dst], stdout=subprocess.PIPE)
        i = 0
        while True:
            line = process.stdout.readline()
            if not line:
                break
            if i > 3:
                if line == b'\r\n':
                    break
                string = self.create_string(line)
                if string:
                    print(string)
                else:
                    break
            i += 1

    def create_string(self, line):
        parts = line.decode('windows-1251', errors='ignore').split()
        string = parts[0] + '\t'

        if parts[1] == '*' and parts[2] == '*' and parts[3] == '*':
            return None
        ip = parts[-1].replace('[', '').replace(']', '')
        if ip.startswith(('10.', '100.64.', '172.16.', '192.168.')):
            info = '\t-\t-\t-'
        else:
            info = self.get_info(ip)
        return string + ip + info

    def get_info(self, ip):
        try:
            with urlopen('https://www.nic.ru/whois/?searchWord=' + ip) as page:
                data = page.read().decode()
        except HTTPError as e:
            print(e)
        AS = re.search(r'AS(\d+)', data)
        if AS:
            ASstr = AS.group(0).strip()
        else:
            ASstr = '-'
        country = re.search(r'country:\s+(.+)\n', data)
        if country and AS:
            country = country.group(1).strip()
        else:
            country = '-'
        descr = re.search(r'descr:\s(.+)\n', data)
        if descr:
            descr = descr.group(1).strip()
        else:
            descr = '-'
        return f'\t{ASstr}\t{country}\t{descr}'


if __name__ == '__main__':
    print('Enter destination address')
    address = input()
    t = Trace(address)
    t.run()
