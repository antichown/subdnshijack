import asyncio
import socket
import optparse
import platform
import subprocess
from colorama import Style, Fore, init
import sys
import tldextract
from datetime import datetime,date
import re

now = datetime.now()

socket.setdefaulttimeout(5)


def whois_regex(domain,data):
    lines8 = data.split("\n")
    for regx in range(9):
        print(Fore.CYAN+"--"+lines8[regx]+Style.RESET_ALL)                    
        if "Expiry Date" in lines8[regx]:
            whois_calculate(domain,lines8[regx])            
            


def whois_calculate(domain,regex_expir):
    now_date = datetime.now()
    year = now_date.strftime("%Y")
    #print("year:", year)
    month = now_date.strftime("%m")
    #print("month:", month)
    day1 = now_date.strftime("%d")
    
    reg_date=re.search("Registry Expiry Date: (.*?)Z", regex_expir)
    if reg_date:
        ex_date=reg_date.group(1)
        ex_date_years=ex_date.split("-")[0]
        ex_date_month=ex_date.split("-")[1]
        ex_date_days=ex_date.split("-")[2]
        
        ex_date_dd=ex_date_days.split("T")[0]
    
        
    date_1 = date(year = int(year), month = int(month), day = int(day1))
    date_2 = date(year = int(ex_date_years), month=int(ex_date_month), day = int(ex_date_dd))
    day_number=date_1-date_2
    str_day=str(day_number)
    if "days" in str_day:
        split_day=str_day.split(" days")[0]
        if int(split_day)>=-150:
            print(Fore.YELLOW+"[----] %s (%s) - day= %s " % (domain,ex_date,split_day)+Style.RESET_ALL)
            print(Fore.RED+"[----] %s VULN (%s) " % (domain,ex_date)+Style.RESET_ALL)    
            
            
    if ex_date_years <= year:
        print(Fore.RED+"[----] %s VULN (%s) " % (domain,ex_date)+Style.RESET_ALL)    
            
            
    
 


def whois_query(domain):
    try:
        proces = subprocess.Popen(['whois', domain],stdout=subprocess.PIPE, stderr=subprocess.STDOUT,encoding='utf-8')
    except Exception as e:
        asad = "whois error"

    try:
        whois_data = proces.communicate()[0]
        whois_regex(domain,whois_data)
    except Exception as e:
        asad = "whois error2"


def location_bypass(sub, location, host):
    global now
    if host not in location:
        new_location = location.replace("location:", "");
        message = "Sub:" + sub + "\nLocation : " + Fore.GREEN + new_location + Style.RESET_ALL
        write_file(host, sub + "\n" + new_location)
        print(message)
        if host not in location:
            print("Out Location : " + Fore.YELLOW + new_location + Style.RESET_ALL)
            tdl_parse = tldextract.extract(new_location.strip())
            main_domain = tdl_parse.domain + "." + tdl_parse.suffix
            whois_query(main_domain)


def write_file(domain, message):
    file = open(domain + "-headers.txt", "a+")
    file.write(message + "\n")
    file.close()


async def senkron_wget(host, dm):
    try:
        connect = asyncio.open_connection(host, 80)
        reader, writer = await connect
        header = 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % host
        writer.write(header.encode('utf-8'))
        await writer.drain()
        while True:
            line = await reader.readline()
            if line == b'\r\n':
                break
            if "location" in line.decode('utf-8'):
                location_bypass(host, line.decode('utf-8'), dm)
            header_lines = '%s header > %s' % (host, line.decode('utf-8').rstrip())
            write_file(dm, header_lines)
        writer.close()
    except Exception as e:
        a = "exception"
    except socket.gaierror as e:
        a = "gaierror"
    except socket.error as e:
        a = "socket error"


def async_loop(file, dm):
    loop = asyncio.get_event_loop()
    print("Scanning...")
    tasks = [senkron_wget(host.strip("\n"), dm) for host in open(file, "r").readlines()]
    loop.run_until_complete(asyncio.wait(tasks))
    loop.close()
    print("Dns Hijack Scan completed,  locationurl.txt saved ")


if __name__ == '__main__':
    try:

        if platform.system() == 'Windows':
            init(autoreset=True)  # winzorta
        parser = optparse.OptionParser()
        parser.add_option('-d',
                          action="store",
                          dest="domain",
                          type="string",
                          help="example: ./subhijack.py -d domain.com")
        parser.add_option('-w',
                          action="store",
                          dest="sublist",
                          type="string",
                          help="example: ./subhijack.py -d domain.com -w sublist.txt ")
        (option, args) = parser.parse_args()

        if not option.domain:
            print("example: ./subhijack.py -d domain.com -w sublist.txt")
            sys.exit(0)

        if not option.sublist:
            print("example: ./subhijack.py -d domain.com -w sublist.txt")
            sys.exit(0)

        print("""
          #######################################################
          #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
          #             Subdomain Dns Hijack Scanner            #
          #                    Coder: 0x94                      #
          #                  twitter.com/0x94                   #
          #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
          #######################################################""")
        async_loop(option.sublist, option.domain)
    except KeyboardInterrupt:
        print('\n Exit.')
        sys.exit(0)
