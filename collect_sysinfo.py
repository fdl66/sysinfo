#!/usr/bin/env python
# Author:           Manuel Zach
# Description:      This script collects information of Solaris and Linux systems.
# Version:          16.09.2012    

# Copyright (c) 2012, Manuel Zach mzach-oss@zach.st
# 
# Permission to use, copy, modify, and/or distribute this software for 
# any purpose with or without fee is hereby granted, provided that the 
# above copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES 
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR 
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES 
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import subprocess
import re
import platform
import os
import sys
import signal
import logging

# Debug level for the whole script
DEBUG_LEVEL=logging.WARNING

cl_cache = {}

# Helper functions

# timeout implementation: 
# Source: http://stackoverflow.com/questions/1191374/subprocess-with-timeout
class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm

def exec_cl(command_line,cache=True,stderr="print"):
    """
        Description: executes a command line and returns the stdout/stderr output of the cli.
        Features:
            - Caching of return values
            - Timeout of called commands (5 minutes)

        Arguments:
            - string command_line: Shell command you like to execute
            - boolean cache: "True" if cached stdout output of command of a prior execution should be used. 
                "False" takes care that command get's executed for every call.
            - string sterr: "print" means the stderr output will be forwarded to stderr. 
                With "hide", the stderr information gets lost.  
                With "return", an array will be returned with [stdout,stderr]

        Return:
            - string: stdout of cli, when called with stderr="print" or stderr="hide"
            - array: [string stdout, string stderr], when called with stderr="return"

        TODO: Improve security by taking care of the PATH env.

    """

    cl_value = ''
    cl_errvalue = ''

    if cache and cl_cache.has_key(command_line):
        logging.debug("exec_cl: found in cache and using it: %s" % command_line)
        cl_value = cl_cache[command_line]
    else:
        logging.info("exec_cl: executed: %s" % command_line)
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(5*60)  # 5 minutes
        try:
            if stderr=="print":
                command = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE)
            else:
                command = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            cl_value, cl_errvalue = command.communicate()

            # remove newline on the end
            # TODO: Replace by fancier solution
            if len(cl_value)> 1 and cl_value[-1]=="\n":
                cl_value=cl_value[:-1]
            if cl_errvalue  and len(cl_errvalue)> 1 and cl_errvalue[-1]=="\n":
                cl_errvalue=cl_errvalue[:-1]

            cl_cache[command_line]=cl_value
        except Alarm:
            sys.stderr.write("Warning: Command timed out: %s\n" % command_line)

    if stderr=="return":
        return [cl_value,cl_errvalue]

    return cl_value

def file_exists(pathname):
    file_test = int(exec_cl("bash -c 'test -e %s ; echo $?'" % pathname))
    if file_test == 0:
        return True
    else:
        return False

class SysAttribute(object):
    """ Parent class of all other classes. 
        Requirements: Does not need id=0, runable on every OS
    """
    name = ""
    value = ""
    last_command = ""

    req_supported_os = [ "Solaris", "Linux" ]
    req_needs_root_linux = False
    req_needs_root_solaris = False
    req_physical_hardware = False
    supported = False

    def __init__(self,attr_name):
        self.name = attr_name
        self.os_name = SysAttribute.get_os()
        self.check_requirements()

    def __str__(self):
        if type(self.value) == type([]):
            return "%s:%s" % (self.name,",".join(self.value))
        return "%s:%s" % (self.name,self.value)

    def simple_run(self,command_line):
        self.last_command = command_line
        self.value=exec_cl(command_line)
        
    @classmethod
    def get_os(cls):
        os_name = exec_cl("uname")

        if os_name == "SunOS":
            os_name = "Solaris"
        return os_name

    @classmethod
    def is_linux(cls):
        if cls.get_os() == "Linux":
            return True
        else:
            return False

    @classmethod
    def is_solaris(cls):
        if cls.get_os() == "Solaris":
            return True
        else:
            return False

    def check_requirements(self):
        req_ok = []
        if SysAttribute.get_os() in self.req_supported_os:
            req_ok.append(True)
        else:
            req_ok.append(False)
            self.supported = False
            return False

        if SysAttribute.is_linux() and self.req_needs_root_linux:
            if os.geteuid()==0:
                req_ok.append(True)
            else:
                req_ok.append(False)
        elif SysAttribute.is_solaris() and self.req_needs_root_solaris:
            if os.geteuid()==0:
                req_ok.append(True)
            else:
                req_ok.append(False)

        if self.req_physical_hardware:
            if not self.is_virtual():
                req_ok.append(True)
            else:
                req_ok.append(False)

        if False in req_ok:
            self.supported = False
            return False
        else:
            self.supported = True
            return True

    @classmethod
    def is_virtual(cls):
        is_virtual = False
    
        if SysAttribute.is_solaris():
            # Detect Solaris local zone
            zonename = exec_cl("zonename")
            if zonename != 'global':
                is_virtual = True
            else:
                # Detect ldom non-control domain, guest domain
                if exec_cl("uname -m") == "sun4v":
                    virtual_devices_exist = file_exists("/devices/virtual-devices@100/channel-devices@200/")
                    hvctl_file_exists = file_exists("/devices/virtual-devices@100/channel-devices@200/virtual-channel@0:hvctl")
                    if virtual_devices_exist and not hvctl_file_exists:
                        is_virtual = True

        if SysAttribute.is_linux():
            # Detects VMware and KVM HV
            lspci_string = exec_cl("/sbin/lspci -m | grep  'VGA compatible controller'")
            lspci_string = lspci_string.upper()
            if "QUMRANET" in lspci_string:
                is_virtual = True
            elif "RED HAT" in lspci_string:
                is_virtual = True
            elif "VMWARE" in lspci_string:
                is_virtual = True

        return is_virtual

class AttrHostname(SysAttribute):
    """ Returns a normalizes hostname. 
    """
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            SysAttribute.simple_run(self,"hostname")

            # Normalization
            self.value = self.value.lower()
            # Only short name, FQDN
            self.value = re.sub(r'\..*','',self.value)

class AttrOS(SysAttribute):
    """ Returns operating system. 
    """
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            self.value = SysAttribute.get_os()

class AttrChassisSN(SysAttribute):
    
    req_supported_os = [ "Solaris", "Linux" ]
    req_needs_root_linux = True
    req_physical_hardware = True
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                sneep_binary = "/usr/sbin/sneep"
                if file_exists(sneep_binary):
                    SysAttribute.simple_run(self,sneep_binary)
                else:
                    self.supported = False
            elif self.is_linux():
                SysAttribute.simple_run(self,"dmidecode -s system-serial-number")
                # Normalize
                self.value = self.value.strip()
            else:
                self.supported = False

class AttrCpuModel(SysAttribute):
    """INFO: Only the model of the one CPU will be reported."""
    
    req_supported_os = [ "Solaris", "Linux" ]
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                SysAttribute.simple_run(self,"kstat -p cpu_info::cpu_info*:brand | tail -1")
                mo = re.search(r'cpu_info:[0-9]*:cpu_info[0-9]*:brand\s*(\S*.*)',self.value)

                if mo:
                    self.value = mo.group(1)
                else:
                    self.value = ""
            elif self.is_linux():
                SysAttribute.simple_run(self,"grep model\ name /proc/cpuinfo | tail -1")
                mo = re.search(r'model\s*name\s*:(.*)',self.value)

                if mo:
                    self.value = mo.group(1)
                else:
                    self.value = ""

            # Normalization
            self.value = self.value.strip()
            self.value = re.sub("\s+"," ",self.value)
            self.value = re.sub(r'\(tm\)',"",self.value)
            self.value = re.sub(r'\(r\)',"",self.value)

class AttrCpuSpeed(SysAttribute):
    
    req_supported_os = [ "Solaris" ,"Linux" ]
    req_needs_root_linux = True
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                SysAttribute.simple_run(self,"kstat -p cpu_info::cpu_info*:clock_MHz | tail -1")
                self.value = self.value.split()[1]
            elif self.is_linux() and not self.is_virtual():
                SysAttribute.simple_run(self,"dmidecode -s processor-frequency")
                # Regex: just match the frequenzy in MHz of the first CPU
                mo = re.search(r'([0-9]*)',self.value)

                if mo:
                    self.value = mo.group(1)
                else:
                    self.value = ""

class AttrCpuCount(SysAttribute):
    """INFO: This attribute counts the physical cpu sockets. """
    
    req_supported_os = [ "Solaris", "Linux" ]
    req_needs_root_linux = True
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                SysAttribute.simple_run(self,"psrinfo -p")
            elif self.is_linux() and not self.is_virtual():
                SysAttribute.simple_run(self,"dmidecode -s processor-manufacturer | wc -l")

class AttrCpuCores(SysAttribute):
    """
    Description: Count of cores per cpu
    Info source on Solaris: kstat -p cpu_info:::core_id | uniq -n 1 | wc -l
    """
    
    req_supported_os = [ "Solaris" ]
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            SysAttribute.simple_run(self,"kstat -p cpu_info:::core_id")
            
            self.value += "\n"
            pattern = re.compile(r'\s[0-9]+\n')
            self.value = len ( set( pattern.findall(self.value) ) )

class AttrVcpuCount(SysAttribute):
    
    req_supported_os = [ "Solaris", "Linux" ]
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                SysAttribute.simple_run(self,"mpstat")
                self.value = len ( self.value.split("\n") ) - 1
            elif self.is_linux():
                SysAttribute.simple_run(self,"grep -c '^processor' /proc/cpuinfo")

class AttrReleaseInfo(SysAttribute):
    
    req_supported_os = [ "Solaris", "Linux" ]
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                SysAttribute.simple_run(self,"cat /etc/release")

                # Normalization
                self.value =  self.value.split("\n")[0]
                self.value = re.sub("(X86)|(SPARC)","",self.value)
                self.value = re.sub("(s10s)|(s10x)","s10",self.value)
                self.value = self.value.strip()
            elif self.is_linux():
                # This should work for /etc/redhat-release and /etc/SuSE-release
                # TODO: Maybe migrate to "lsb_release -d"
                SysAttribute.simple_run(self,"cat /etc/*-release")

        
class AttrMemory(SysAttribute):
    
    req_supported_os = [ "Solaris", "Linux" ]
    req_needs_root_linux = True
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                # BUG: prtconf  is not working on intel solaris zones
                memory_raw = exec_cl("prtconf -p | grep Memory")
                memory_mo = re.search(r'Memory size:\s*([0-9]*)\s*Megabytes', memory_raw)

                if memory_mo:
                    memory = memory_mo.group(1)
                else:
                    memory = ""
                self.value = memory

            if self.is_linux():
                memory_dimms_raw = exec_cl("dmidecode -t memory | grep Size:") 
                memory = 0
                for memory_dimm in memory_dimms_raw.split('\n'):
                    memory_mo = re.search(r'^\s+Size\:\s+([0-9]+)\s+(MB|GB)', memory_dimm)
                    if memory_mo:
                        dimm_value = int(memory_mo.group(1))
                        if memory_mo.group(2)=="GB":
                            memory = memory + (dimm_value * 1024.0)
                        else:
                            memory = memory + dimm_value
                self.value = memory

            # Normalization
            # Convert MB to GB
            try:
                self.value = "%.2f" %  (int(self.value) / 1024.0) 
            except:
                self.value = ""
                logging.warning("Could not get value for memory configuration.")

class AttrHardwareModel(SysAttribute):

    req_supported_os = [ "Solaris", "Linux" ]
    req_needs_root_linux = True
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                arch = platform.processor()
                if arch == "sparc":
                    model_raw = exec_cl("prtconf -pv | grep banner-name")
                    model_mo = re.search(r'banner-name:\s*\'(.*)\'',model_raw)
                else:
                    #Intel
                    model_raw = exec_cl("smbios -t SMB_TYPE_SYSTEM")
                    model_mo = re.search(r'Product:\s*(\S.*)\n',model_raw)

                if model_mo:
                    model = model_mo.group(1)
                else:
                    model = ""
                self.value = model
            elif self.is_linux():
                self.value = exec_cl("dmidecode -s system-product-name")
                # Normalize
                self.value = self.value.strip()

class AttrHardwareManufacturer(SysAttribute):

    req_needs_root_linux = True
    
    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            if self.is_solaris():
                # TODO: replace by exec_cl and move to SysAttribute
                arch = platform.processor()
                if arch == "sparc":
                    manufacturer_raw = exec_cl("showrev")
                    manufacturer_mo = re.search(r'Hardware provider:\s*(\S.*)\n',manufacturer_raw)
                else:
                    #Intel
                    manufacturer_raw = exec_cl("smbios -t SMB_TYPE_SYSTEM")
                    manufacturer_mo = re.search(r'Manufacturer:\s*(\S.*)\n',manufacturer_raw)

                if manufacturer_mo:
                    manufacturer = manufacturer_mo.group(1)
                else:
                    manufacturer = ""
                self.value = manufacturer

                # Normalization
                self.value = re.sub("_"," ",self.value)
                self.value = self.value.strip()
            elif self.is_linux():
                self.value = exec_cl("dmidecode -s system-manufacturer")

class AttrCoreFactor(AttrHardwareModel,AttrCpuCores,AttrCpuModel,AttrCpuSpeed):

# http://www.oracle.com/us/corporate/contracts/processor-core-factor-table-070634.pdf

# Algorithm:
# 1. sysinfo_string it generated in the following form:
#   Server model;cpu name;cpu speed in Mhz; sum of all cores
#   E.g.
#   Sun SPARC Enterprise M5000 Server;SPARC64-VII;2400Mhz;8
#   Ultra 24:Intel(r) Core(tm)2 Quad CPU    Q9650  @ 3.00GHz:3000Mhz:8
# 2. The core_factor_table list is walked down until the regex pattern matches. If
#   the pattern matches the value in the tuble is used as factor for the cores.
#   The core_factor_table is a ordered list of tubles:
#   core_factor_table = [ (<regex-pattern1>, <cpu-core-factor1>), 
#                           (<regex-pattern2>, <cpu-core-factor2>) ]

    req_supported_os = [ "Solaris" ]
    req_physical_hardware = True

# Regex reminder
# Escape chars like +?)(

# core_factor_table was updated on Sept 2011
    core_factor_table = [ ( r';UltraSPARC-T1;1[0|2]00Mhz;', 0.25 ),
                     ( r';UltraSPARC-T1;1400Mhz;', 0.5 ),
                     ( r';SPARC64-VII\+;', 0.5 ),
                     ( r';UltraSPARC-T2\+;', 0.5 ),
                     ( r';UltraSPARC-IIIi;', 0.75 ),
                     ( r';UltraSPARC-IV;', 0.75 ),
                     ( r';UltraSPARC-IV\+;', 0.75 ),
                     ( r';UltraSPARC-T2;', 0.75 ),
                     ( r'AMD Opteron Processor', 0.5 ),
                     ( r'Intel', 0.5 ),
                     ( r';SPARC64-VI;', 0.75 ),
                     ( r';SPARC64-VII;', 0.75 ) ]

    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:

            # Build licensing_sysinfo_string
            AttrHardwareModel.__init__(self,attr_name)
            model = self.value
            AttrCpuCores.__init__(self,attr_name)
            cpu_cores = self.value
            AttrCpuModel.__init__(self,attr_name)
            cpu_name = self.value
            AttrCpuSpeed.__init__(self,attr_name)
            cpu_speed = self.value

            licensing_sysinfo_string = ";".join( [ model,
                                                    cpu_name,
                                                    str(cpu_speed)+"Mhz",
                                                    str(cpu_cores)])

            # Lookup the core factor
            matched_pattern = "Not found"
            core_factor = 1
            for pattern in self.core_factor_table:
                if re.search(pattern[0],licensing_sysinfo_string):
                    matched_pattern = pattern[0]
                    core_factor = pattern[1]
                    break
            self.value = cpu_cores * core_factor

class AttrIsVirtual(SysAttribute):
    
    req_supported_os = [ "Solaris", "Linux" ]

    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            self.value = str(SysAttribute.is_virtual())

class AttrVirtualizes(SysAttribute):
    
    req_supported_os = [ "Solaris" ]
    req_needs_root_solaris = True

    def __init__(self,attr_name):
        virtual_servers = []
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            self.value = ""

            # Discover guest ldoms
            if self.supported and file_exists("/usr/sbin/ldm") and file_exists("/devices/virtual-devices@100/channel-devices@200/virtual-channel@0:hvctl"):
                import telnetlib
                ldm_list_raw = exec_cl("/usr/sbin/ldm list -p | grep state=active")
                consoles = re.findall(r'cons=([0-9]+)', ldm_list_raw)

                for console in consoles:
                    tn = telnetlib.Telnet("127.0.0.1",console)
                    # For debugging
                    #tn.set_debuglevel(1)

                    tn.write("\n\n\n")
                    mo = tn.expect([r' (\S*) console login',r'} (ok)'],2)
                    tn.close()
                    if mo[1]:
                        ldom_hostname = mo[1].group(1)
                        if ldom_hostname != 'ok':
                            virtual_servers.append(ldom_hostname)

            # Discover Solaris local zones
            if self.supported and exec_cl("zonename") == "global":
                local_zones = exec_cl("zoneadm list").split("\n") 
                local_zones_hostname = [] 
                if "global" in local_zones: 
                    local_zones.remove("global") 

                for local_zone in local_zones: 
                    zone_hostname = exec_cl("zlogin -S %s hostname" % local_zone) 
                    local_zones_hostname.append(zone_hostname) 
                virtual_servers.extend(local_zones_hostname)

            self.value = virtual_servers
            

class AttrIlomAdress(SysAttribute):
    
    req_supported_os = [ "Solaris" ]
    req_needs_root_solaris = True
    req_physical_hardware = True

    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)
        if self.supported:
            self.value = AttrIlomAdress.get_ilom_network()[1]

    @classmethod
    def get_ilom_network(cls):
            ilom_ip_value = ''
            ilom_mask_value = ''
            mac_address_value = ''
            sys.stderr.write("INFO: IPMI query started, could take some minutes.\n")
            ipmiinfo_raw = exec_cl("/opt/sun/n1gc/pkgs/usr/sbin/ipmitool lan print",stderr="hide")
            sys.stderr.write("INFO: IPMI query finished\n")
            ip_mo = re.search(r'\nIP Address\s*:\s*([0-9.]*)\n',ipmiinfo_raw)
            if ip_mo:
                ilom_ip_value = ip_mo.group(1)
            mask_mo = re.search(r'\nSubnet Mask\s*:\s*([0-9.]*)\n',ipmiinfo_raw)
            if mask_mo:
                ilom_mask_value = mask_mo.group(1)
            mac_mo = re.search(r'\nMAC Address\s*:\s*([0-9a-zA-Z:]*)\n',ipmiinfo_raw)
            if mac_mo:
                mac_address_value = mac_mo.group(1)

            return ['ilo', ilom_ip_value, ilom_mask_value, mac_address_value, 'empty']

class AttrNetwork(SysAttribute):

    req_supported_os = [ "Solaris", "Linux" ]
    uninteresting_nics = ["lo","sppp","clprivnet"]

    def __init__(self,attr_name):
        SysAttribute.__init__(self,attr_name)

        if self.supported:
            nics_info = []
            if self.is_solaris():
                ifconfig_raw = exec_cl("ifconfig -a4Z")
                ifconfig_nic_linebreak = "\t"
                regex_nic = r'([a-zA-z0-9]*):'
                regex_mac = r'\tether\s*([0-9a-zA-Z:]*)\s'
                regex_ip = r'\tinet\s*([0-9.]*)\s'
                regex_netmask = r'\snetmask\s*([0-9a-z]*)\s'

                if not SysAttribute.is_virtual():
                    ilom_nic = AttrIlomAdress.get_ilom_network()
                    if ilom_nic[1]!='':
                        nics_info.append(" ".join(ilom_nic))

            elif self.is_linux():
                ifconfig_raw = exec_cl("/sbin/ifconfig | grep -A1 HWaddr | grep -E 'HWaddr|inet '")
                ifconfig_nic_linebreak = " "
                regex_nic = r'([a-zA-z0-9]*)'
                regex_mac = r'HWaddr\s*([0-9a-zA-Z:]*)'
                regex_ip = r'inet addr:\s*([0-9.]*)\s'
                regex_netmask = r'\sMask:\s*([0-9a-z.]*)\s*'

            # split up the ifconfig output in a array with one nic per item
            lines = ifconfig_raw.split("\n")
            nic_strings = []
            if len(lines)>0 and lines[0]!='':
                for line in lines:
                    if line[0]!= ifconfig_nic_linebreak:
                        nic_strings.append(line)
                    else:
                        nic_strings[-1] += line

            for nic_string in nic_strings:
                nic_mac = 'empty'
                nic_mac_mo = re.search(regex_mac, nic_string)    
                if nic_mac_mo:
                    nic_mac = nic_mac_mo.group(1)
                    # Normalize
                    nic_mac = nic_mac.upper()
                    # 0:1B:4A:8C:AA:A2 => 00:1B:4A:8C:AA:A2 
                    nic_mac = ":".join( map(lambda x: x.rjust(2,'0') ,nic_mac.split(':')) )

                nic_name = 'empty'
                nic_name_mo = re.match(regex_nic, nic_string)    
                if nic_name_mo:
                    nic_name = nic_name_mo.group(1)

                nic_ip = 'empty'
                if nic_mac[:6]!='0:0:0:':
                    nic_ip_mo = re.search(regex_ip, nic_string)    
                    if nic_ip_mo:
                        nic_ip = nic_ip_mo.group(1)

                    nic_netmask = 'empty'
                    nic_netmask_mo = re.search(regex_netmask, nic_string)    
                    if nic_netmask_mo:
                        nic_netmask = nic_netmask_mo.group(1)
                        # Normalize
                        # convert to numeric, if netmask is in hex
                        if len(nic_netmask)==8:
                            nic_netmask_octets = re.findall(r'[0-9a-fA-F]{2}',nic_netmask)
                            nic_netmask = ".".join( map(lambda octet: str( int(octet,16) ), nic_netmask_octets) )

                    # ha_group is atm only implemented for Solaris IPMP groups
                    nic_ha_group = 'empty'
                    nic_ha_group_mo = re.search(r'\tgroupname\s*(\S*)', nic_string)    
                    if nic_ha_group_mo:
                        nic_ha_group = nic_ha_group_mo.group(1)

                    nics_info.append("%s %s %s %s %s" % (nic_name,nic_ip,nic_netmask,nic_mac,nic_ha_group) )

            self.value = nics_info
            # Normalization
            # Remove uninteresting nics
            self.value = [ nic for nic in self.value if re.sub(r'[0-9:]*','',nic.split()[0]) not in self.uninteresting_nics ]



def main():
    logging.basicConfig(level=DEBUG_LEVEL)
    script_filename = os.path.basename( __file__ )
    script_filename_absolute =  os.path.abspath( __file__ )

    # Create a list of all objects
    object_list = []    

    hostname = AttrHostname("hostname")
    object_list.append(hostname)

    manufacturer = AttrHardwareManufacturer("manufacturer")
    object_list.append(manufacturer)

    hardware_model = AttrHardwareModel("hardware_model")
    object_list.append(hardware_model)

    chassis_sn = AttrChassisSN("chassis_sn")
    object_list.append(chassis_sn)

    operating_system = AttrOS("os_name")
    object_list.append(operating_system)

    is_virtual = AttrIsVirtual("is_virtual")
    object_list.append(is_virtual)

    memory = AttrMemory("memory")
    object_list.append(memory)

    cpu_model = AttrCpuModel("cpu_model")
    object_list.append(cpu_model)

    cpu_speed = AttrCpuSpeed("cpu_speed")
    object_list.append(cpu_speed)

    cpu_count = AttrCpuCount("cpu_count")
    object_list.append(cpu_count)

    cpu_cores = AttrCpuCores("cpu_cores")
    object_list.append(cpu_cores)

    vcpu_count = AttrVcpuCount("vcpu_count")
    object_list.append(vcpu_count)

    core_factor = AttrCoreFactor("oracle_core_sum")
    object_list.append(core_factor)

    release_info = AttrReleaseInfo("release_info")
    object_list.append(release_info)

    virtual_servers = AttrVirtualizes("virtual_servers")
    object_list.append(virtual_servers)

    ilom_address = AttrIlomAdress("ilo_address")
    object_list.append(ilom_address)

    network_info = AttrNetwork("network_info")
    object_list.append(network_info)

    # Print header line
    header = ""
    for o in object_list:
        header += o.name
        header += ";"

    header = header[:-1]

    # TODO: improve
    virtual_instances_csv = []

    if operating_system.is_linux():
        print header
    if operating_system.is_solaris():
        if not "/var/tmp/" in script_filename_absolute:
            print header

        # discovery of local solaris zones
        if operating_system.is_solaris() and os.geteuid()==0 and exec_cl("zonename") == "global":
            zoneadm_raw = exec_cl("zoneadm list -v | grep -v global")
            zoneadm_info = re.findall(r'\s(\S*)\s*running\s*(\S*)\s', zoneadm_raw)

            for zone in zoneadm_info:
                zonename = zone[0]
                zonepath = zone[1]
                sys.stderr.write("INFO: Starting discovery on local zone %s\n" % zonename)
                deploy_returncode =  exec_cl("cp %s %s/root/var/tmp/ ; echo $?" % (script_filename_absolute,zonepath), cache=False )
                if deploy_returncode != "0":
                    print "Warning: Deployment of discovery script in %s failed." % zonename
                else:
                    virtual_instances_csv.append(exec_cl("zlogin %s 'python /var/tmp/%s'" % (zonename,script_filename) ))

    # Print CSV
    csv_output = ""
    for o in object_list:
        if o.supported:
            if type(o.value) == type([]):
                csv_output += ",".join(o.value)
            else:    
                csv_output += str(o.value)
        csv_output += ";"
    csv_output = csv_output[:-1]

    if len(virtual_instances_csv)>0:
        virt_csv_output = "\n".join(virtual_instances_csv)
        if virt_csv_output[-1]=='\n':
            virt_csv_output = virt_csv_output[:-1]
        print virt_csv_output
    print csv_output

if __name__=="__main__":
    main()
