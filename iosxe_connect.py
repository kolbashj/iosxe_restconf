import json
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class IosxeConnect:
    """
    Class to interact with RESTCONF configuration, operational and RPC methods on
        Cisco IOS XE Devices.

        Note: Tested only on Catalyst 8000v.
                Cisco IOS XE Software, Version 17.12.04

    USAGE:
        1. Import the class from the module.
        2. Specify hostname, username and password when initializing the class.
        Example:
        
            from iosxe_connect import IosxeConnect
            iosxe = IosxeConnect('192.168.150.1', 'admin', 'Cisco123')

    Can be used for device configuration by leveraging typical CRUD methods:
        POST, PATCH, PUT, & DELETE
        Example:
        
            iosxe.post(api_path, data)
                where api_path is the path of the RESTCONF API endpoint
                and data is the JSON-encoded payload.

    Includes generic GET operation for querying any valid Restconf path.
        Example:
        
            iosxe.get(api_path)

    Includes the following callable methods for returning operational data Cisco IOS XE devices:

        aaa, acl, archive, bfd, bgp, bgp_neighbors, bgp_summary, cpu, dev_hw (device-hardware),
        env (Fan, Power, Temperature), fib, flow_mon (netflow config), interfaces, ipsla, lldp,
        memory, mem_proc (per-process memory), mpls_fwd, mpls_ldp, nat, ntp, ospf, plat_sw

        These specific operations will return a dictionary containing the results.

        Example:
        
            iosxe.cpu()

    Includes the following operational methods:

        iosxe.reload() - Reboots the device
        iosxe.write_mem() - Saves running-config to startup-config
        iosxe.show_run() - Returns the running configuration in restconf-json format
    """

    def __init__(self, hostname: str, username: str, password: str):
        """
        :param hostname: Device hostname or IP address
        :param username: HTTP(s) Username
        :param password: HTTP(s) Password
        """
        self.hostname = hostname
        self.username = username
        self.password = password

        self.url_base = f'https://{self.hostname}/restconf/'
        self.verify = False

        self.headers = {'Accept': 'application/yang-data+json',
                        'Content-Type': 'application/yang-data+json',
                        'Connection': 'keep-alive',
                        'Accept-Encoding': 'gzip, deflate, br'
                        }

        self.request = {'headers': self.headers,
                        'auth': (self.username, self.password),
                        'verify': self.verify,
                        }

    def repr(self):
        return (f'IosxeMonitor(hostname={self.hostname}, '
                f'username={self.username}, '
                f'password={self.password})')

    def str(self):
        self.request['url'] = self.url_base
        return str(self.request)

    def __call__(self) -> dict:
        self.request['url'] = self.url_base
        return requests.get(**self.request).json()

    def get(self, api_path) -> dict:
        self.request['url'] = self.url_base + api_path
        return requests.get(**self.request).json()

    def post(self, api_path, data) -> requests.Response:
        self.request['url'] = self.url_base + api_path
        self.request['data'] = json.dumps(data)
        return requests.post(**self.request)

    def put(self, api_path, data) -> requests.Response:
        self.request['url'] = self.url_base + api_path
        self.request['data'] = json.dumps(data)
        return requests.put(**self.request)

    def patch(self, api_path, data) -> requests.Response:
        self.request['url'] = self.url_base + api_path
        self.request['data'] = json.dumps(data)
        return requests.patch(**self.request)

    def delete(self, api_path, data) -> requests.Response:
        self.request['url'] = self.url_base + api_path
        self.request['data'] = json.dumps(data)
        return requests.delete(**self.request)

    def show_run(self) -> dict:
        """
        Returns the running-configuration
        Equivalent to 'show running-config | format restconf-json'
        :return:
        """
        self.request['url'] = self.url_base + 'data/Cisco-IOS-XE-native:native'
        return requests.get(**self.request).json()

    def reload(self) -> requests.Response:
        """
        Reload the device
        :return:
        """
        self.request['url'] = self.url_base + 'operations/Cisco-IOS-XE-rpc:reload'
        return requests.post(**self.request)

    def write_mem(self) -> requests.Response:
        """
        Save configuration to NVRAM
        Equivalent to copy running-config startup-config
        :return:
        """
        self.request['url'] = self.url_base + 'operations/cisco-ia:save-config'
        return requests.post(**self.request)

    # =============================================
    # THE FOLLOWING METHODS ARE USED FOR COLLECTING
    # DEVICE METRICS AND OPERATIONAL DATA
    # Includes aaa() through routes()
    # =============================================
    def aaa(self) -> dict:
        """
        AAA = Authentication, Authorization & Accounting
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-aaa-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-aaa-oper:aaa-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def acl(self) -> dict:
        """
        ACL = Access control Lists
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-acl-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-acl-oper:access-lists'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def archive(self) -> dict:
        """
        Archive configuration info
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-checkpoint-archive-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-checkpoint-archive-oper:checkpoint-archives'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def bfd(self) -> dict:
        """
        BFD - Bi-Directional Forwarding Detection
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-bfd-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-bfd-oper:bfd-state'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def bgp(self) -> dict:
        """
        BGP - Border Gateway Protocol
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-bgp-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-bgp-oper:bgp-state-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def bgp_neighbors(self) -> dict:
        """
        BGP - Border Gateway Protocol - neighbors/neighbor
        Extends Yang path to include only BGP neighbor info
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-bgp-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-bgp-oper:bgp-state-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]['neighbors']['neighbor']

    def bgp_summary(self) -> dict:
        """
        BGP - Border Gateway Protocol - /address-families/address-family
        Extends Yang path to include only BGP Summary info
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-bgp-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-bgp-oper:bgp-state-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]['address-families']['address-family']

    def cpu(self) -> dict:
        """
        CPU - CPU Utilization
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-process-cpu-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-process-cpu-oper:cpu-usage'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]['cpu-utilization']

    def dev_hw(self) -> dict:
        """
        Device Hardware Information
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-device-hardware-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-device-hardware-oper:device-hardware-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def env(self) -> dict:
        """
        Environment Sensors - Power, Fans, Temperature
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-environment-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-environment-oper:environment-sensors'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    # Chunking Exception happening for FIB using python
    # Resolved by adding /fib-ni-entry path
    def fib(self) -> dict:
        """
        FIB - Forwarding Information Base
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-fib-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-fib-oper:fib-oper-data/fib-ni-entry'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()

    def flow_mon(self) -> dict:
        """
        Netflow Configuration Information
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-flow-monitor-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-flow-monitor-oper:flow-monitors'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def interfaces(self) -> dict:
        """
        Interface Metrics
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-interfaces-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-interfaces-oper:interfaces'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]['interface']

    def ipsla(self) -> dict:
        """
        IP SLA test data
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-ip-sla-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-ip-sla-oper:ip-sla-stats'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def lldp(self) -> dict:
        """
        LLDP info - Local Settings. Does not show neighbor information
        :return:
        """
        yang_path = 'Cisco-IOS-XE-lldp-oper:lldp-entries'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def memory(self) -> dict:
        """
        Device Memory Usage
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-memory-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-memory-oper:memory-statistics'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]['memory-statistic']

    def mem_proc(self) -> dict:
        """
        Process Memory Usage
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-process-memory-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-process-memory-oper:memory-usage-processes'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]['memory-usage-process']

    def mpls_fwd(self) -> dict:
        """
        MPLS Forward Table Info
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-mpls-forwarding-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-mpls-forwarding-oper:mpls-forwarding-oper-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def mpls_ldp(self) -> dict:
        """
        MPLS LDP Info
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-mpls-ldp-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-mpls-ldp-oper:mpls-ldp-oper-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def nat(self) -> dict:
        """
        NAT Entries and statistics
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-nat-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-nat-oper:nat-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def ntp(self) -> dict:
        """
        NTP Operational Info
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-ntp-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-ntp-oper:ntp-oper-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def ospf(self) -> dict:
        """
        OSPF data
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-ospf-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-ospf-oper:ospf-oper-data'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def plat_sw(self) -> dict:
        """
        Platform Software info, File System / Disk Information
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-platform-software-oper.yang
        :return:
        """
        yang_path = 'Cisco-IOS-XE-platform-software-oper:cisco-platform-software'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()[yang_path]

    def routes(self) -> dict:
        """
        Route Tables
        https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-platform-software-oper.yang
        :return:
        """
        yang_path = 'ietf-routing:routing-state'
        self.request['url'] = self.url_base + 'data/' + yang_path
        return requests.get(**self.request).json()
    
