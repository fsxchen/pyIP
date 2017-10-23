#!/usr/bin/env python
# -*- coding:utf-8 -*- 
"""

File Name: pyIP/pyIP.py
Description: 
Created_Time: 2017-03-02 14:49:28
Last modified: 2017-03-02 17时13分00秒
"""

_author = 'arron'
_email = 'fsxchen@gmail.com'
import sys
import os, re
import socket, struct


ip_reg = "^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$"
ip_pattern = re.compile(ip_reg)


def is_ipaddr(addrstr):
    """
    判定一个字符串是否是一个合法的IP地址
    :param addrstr: 字符串
    :return: bool
    """
    return True if re.match(ip_pattern, addrstr) else False


def is_net_mask(netmaskstr):
    """
    判断是否是一个合法的ip/netmask格式的IP地址
    :param netmaskstr:
    :return: bool
    """
    if "/" in netmaskstr:
        try:
            ip, netmask = netmaskstr.split("/")
        except Exception as e:
            print(e)
        if re.match(ip_pattern, ip) is not None and int(netmask) <= 32 and int(netmask) >=0:
            return True
        else:
            return False
    else:
        return False


def is_ip_range_s(iprangestr):
    """
    判断一个ip地址是否为一个比较短ip范围， 192.168.0.1-254
    :param iprangestr:
    :return: bool
    """
    if "-" in iprangestr:
        try:
            ipStart, end = iprangestr.split("-")
        except Exception as e:
            print(e)

        if re.match(ip_pattern, ipStart) is not None:
            try:
                return True if 0 < int(end) and int(end) <= 255 else False       #like 192.168.1-255
            except Exception as e:
                print(e)                          
        else:
            return False
    else:
        return False


def is_ip_range_l(iprangestr):
    """
    判断一个ip地址是否为一个比较长ip范围， 192.168.0.1-192.168.1.254
    :param iprangestr:
    :return: bool
    """
    if "-" in ipRange:
        try:
            ip_start, end = iprangestr.split("-")
        except Exception as e:
            print(e)

        if re.match(ip_pattern, iprangestr) and re.match(ip_pattern, end):
            return True
        return False
    else:
        return False

def ip_create(line):
    """
    Create ip address
    
    Args:
        line: a string
    
    Returns:
        an ip generate
    """
    if is_ipaddr(line):
        yield line.strip()
    elif is_net_mask(line):                     # if it likes  192.168.1.0/24
        ip ,netmask = line.split("/")
        netmask = int(netmask)
        hoip = socket.ntohl(struct.unpack("i",socket.inet_aton(ip))[0])
        for i in range(1, 2**(32 - netmask) - 1):
            hoip = int(hoip) + 1
            ip =  socket.inet_ntoa(struct.pack('I',socket.ntohl(hoip)))
            yield ip

    elif is_ip_range_s(line):
        ipstart, end = line.split("-")
        point = [int(ipstart.split(".")[-1]), int(end)] if (int(end) > int(ipstart.split(".")[-1]))  else [int(end), int(ipstart.split(".")[-1])]
        interval = point[1] - point[0]
        
        ipstartlist = ipstart.split(".")
        ipstartlist[-1], ste = [str(point[0]), interval ] if point[0] == 0 else [str(point[0] - 1), interval + 1]
        ipstart = ".".join(ipstartlist)
        hoip = socket.ntohl(struct.unpack("I",socket.inet_aton(ipstart))[0])
    
        ste =  ste - 1  if point[1] == 255  else ste
        slist = list(range(ste)) 
        for i in slist:
            hoip = int(hoip) + 1
            ip = socket.inet_ntoa(struct.pack('I',socket.ntohl(hoip)))
            yield ip

    elif is_ip_range_l(line):
        ipstart, ipend = line.split("-")
        IipStart = socket.ntohl(struct.unpack("I",socket.inet_aton(ipstart))[0])
        IipEnd = socket.ntohl(struct.unpack("I",socket.inet_aton(ipend))[0])
        ipArry = [IipStart, IipEnd] if IipStart < IipEnd else [IipEnd, IipStart]
        interval = ipArry[1] - ipArry[0]
        for i in range(interval - 1):
            ipArry[0] = ipArry[0] + 1
            ip = socket.inet_ntoa(struct.pack('I',socket.ntohl(ipArry[0])))
            yield ip


def ip2cidrip(ip):
    """
    将一个ip地址，找出其对应的cidr网络
    :param ip:
    :return: cidr IP地址
    """
    if is_ipaddr(ip):
        A, B, C, D = ip.split(".")
        if int(A) <= 127:
            cidrip = A + ".0.0.0/8"
            return cidrip
        elif int(A) <= 191 and int(A) > 127:
            cidrip = A + '.' + B + '.0.0/16'
            return cidrip
        elif int(A) < 224 and int(A) > 191:
            cidrip = A + '.' + B + '.' + C + '.0/24'
            return cidrip
    else:
        return


def get_ip_from_file(filename):
    """
    从一个文件中获取ip地址
    :param filename:
    :return:  ips
    """
    with open(filename) as fd:
        for line in fd:
            yield ip_create(line.strip())


def ip_handle(astr):
    """
    得到一群IP地址
    :param astr: 输入的是一个字符串
    :return:
    """
    if type(astr) is str:
        # 如果传入的字符是一个文件名
        if os.path.isfile(astr):
            for ip in get_ip_from_file(astr):
                yield ip
        else:
            yield ip_create(astr)

    elif type(astr) is list:
        for ip in astr:
            if is_ipaddr(ip) or is_net_mask(ip) or is_ip_range_l(ip) or is_ip_range_s():
                yield ip_create(ip)
    elif type(astr) is tuple:
        for a in astr:
            for ip in a:
                if is_ipaddr(ip) or is_net_mask(ip) or is_ip_range_s(ip) or is_ip_range_l(ip):
                    yield ip_create(ip)
    else:
        pass    
if __name__ == "__main__":
    for ip_generate in ip_handle(sys.argv[1]):
        for ip in ip_generate:
            print(ip)
