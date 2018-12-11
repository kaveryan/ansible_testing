#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import sys
import json
from collections import namedtuple
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.inventory.manager import InventoryManager
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.plugins.callback import CallbackBase
import chardet
from pprint import pprint
reload(sys)
sys.setdefaultencoding('utf-8')
type=sys.getfilesystemencoding()

class MyCallBack(CallbackBase):
    #这里是状态回调
    def __init__(self,*args):
        super(MyCallBack,self).__init__(display=None)
        self.status_ok=json.dumps({})
        self.status_fail=json.dumps({})
        self.status_unreachable=json.dumps({})
        self.status_playbook=''
        self.status_no_hosts=False
        self.result = {}

    def get_result(self,host,result,code):
        if not self.result.has_key(str(host)):
            self.result[str(host)] = []
        result_dict = {
            "code": code,
            "task": str(result._task).split("TASK: ")[1],
        }
        try:
            if result._result.has_key('cmd'):
                result_dict["command"] = result._result['cmd']
                result_dict["result"] = {
                    "stderr": result._result['stderr'],
                    "stdout": result._result['stdout'],
                    "stdout_lines": result._result['stdout_lines'],
                }
            elif result._result.has_key('msg'):
                result_dict["result"] = {
                    "stderr": str(result._result['msg']).replace("'",'"').replace('"',""),
                    "stdout": None,
                    "stdout_lines": None,
                }
            elif result._result.has_key('original_basename'):
                result_dict["command"] = result._result['operation']
                result_dict["result"] = {
                    "stderr": result._result['stderr'],
                    "stdout": result._result['changed'],
                    "stdout_lines": "source: " + result._result['src'] + ", destination: " + result._result['dest'] + ", result: " + result._result['changed'],
                }
        except Exception as e:
            result_dict["result"] = {
                    "stderr": result._result,
                    "stdout": None,
                    "stdout_lines": None,
                }
        finally:
            self.result[str(host)].append(result_dict)

    def v2_runner_on_ok(self,result):
        host=result._host.get_name()
        self.runner_on_ok(host, result._result)
        self.get_result(result._host,result,"OK")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        host = result._host.get_name()
        self.runner_on_failed(host, result._result, ignore_errors)
        self.get_result(result._host,result,"FAILED")

    def v2_runner_on_unreachable(self, result):
        host = result._host.get_name()
        self.runner_on_unreachable(host, result._result)
        self.get_result(result._host,result,"UNREACHABLE")

    def v2_playbook_on_no_hosts_matched(self):
        self.playbook_on_no_hosts_matched()
        self.status_no_hosts=True
    def v2_playbook_on_play_start(self, play):
        self.playbook_on_play_start(play.name)
        self.playbook_path=play.name

class MyInventory(object):
    def __init__(self, inventory):
        Options = namedtuple('Options', ['connection', 'module_path', 'forks', 'become', 'become_method', 'become_user', 'check', 'diff', 'remote_user'])
        self.loader = DataLoader()
        self.options = Options(
                connection = inventory.get('connection','smart'),
                module_path = inventory.get('module_path'),
                forks = inventory.get('forks',100),
                become = inventory.get('become'),
                become_method = inventory.get('become_method'),
                become_user = inventory.get('become_user'),
                remote_user = inventory.get('remote_user'),
                check = inventory.get('check',False),
                diff = inventory.get('diff',False),
            )
        self.passwords = dict(
                become_pass = inventory.get('become_pass'),
                conn_pass = inventory.get('conn_pass'),
            )
        self.Inventory = InventoryManager(loader=self.loader)
        self.groups = inventory.get('groups')
        self.port = inventory.get('port')
        for group in self.groups:
            groupname = group.get('groupname')
            if groupname:
                self.Inventory._inventory.add_group(group.get('groupname'))
                for host in group.get('hosts'):
                    self.Inventory._inventory.add_host(host['hostname'],groupname)
                    if host.has_key('variable'):
                        for key in host['variable'].keys():
                            self.Inventory._inventory.set_variable(host['hostname'],key,host['variable'][key])
        self.variable_manager = VariableManager(loader=self.loader, inventory=self.Inventory)

class MyPlay(object):
    def __init__(self, data, MyInventory):
        self.play = Play().load(data, variable_manager=MyInventory.variable_manager, loader=MyInventory.loader)

class TaskQueue(object):
    def __init__(self, MyInventory, MyCallBack):
        self.TaskQueueManager = TaskQueueManager(
                inventory=MyInventory.Inventory,
                variable_manager=MyInventory.variable_manager,
                loader=MyInventory.loader,
                options=MyInventory.options,
                passwords=MyInventory.passwords,
                stdout_callback=MyCallBack,  # Use our custom callback instead of the ``default`` callback plugin
            )


if __name__ == '__main__':
    inventory = {
        "groups": [
            {
                "groupname": "local",
                "hosts": [
                    # {
                    # "hostname": "10.205.37.165",
                    # "variable":{
                    #         "ansible_user": "administrator",
                    #         "ansible_password": "abc@123",
                    #         "ansible_port": "5986",
                    #         "ansible_connection": "winrm",
                    #         "ansible_winrm_server_cert_validation":"ignore",
                    #     }
                    # },
                    # {
                    #     "hostname": "10.205.38.165",
                    #     "variable":{
                    #             "ansible_user": "administrator",
                    #             "ansible_password": "abc@123",
                    #             "ansible_port": "5986",
                    #             "ansible_connection": "winrm",
                    #             "ansible_winrm_server_cert_validation":"ignore",
                    #         }
                    #     },
                    # {
                    # "hostname": "127.0.0.1",
                    # "variable":{
                    #         "ansible_user": 'root',
                    #         "ansible_password": 'kaver1',
                    #         "ansible_port": "22",
                    #         "ansible_connection": "ssh",
                    #         "ansible_ssh_common_args" : "-o StrictHostKeyChecking=no",
                    #     }
                    # },
                    {
                    "hostname": "172.16.10.21",
                    "variable":{
                            "ansible_user": "administrator",
                            "ansible_password": "Passw0rd",
                            "ansible_port": "5986",
                            "ansible_connection": "winrm",
                            "ansible_winrm_server_cert_validation":"ignore",
                        }
                    },
                    # {
                    # "hostname": "172.16.10.22",
                    # "variable":{
                    #         "ansible_user": "root",
                    #         "ansible_password": "kaver1",
                    #         "ansible_port": "22",
                    #         "ansible_connection": "ssh",
                    #         "ansible_ssh_common_args" : "-o StrictHostKeyChecking=no",
                    #     }
                    # },
                ],
            },
            # {
            #     "groupname": "linux",
            #     "hosts": [{
            #         "hostname": "172.16.10.22",
            #         "variable":{
            #                 "ansible_user": "root",
            #                 "ansible_password": "kaver1",
            #                 "ansible_port": "22",
            #                 "ansible_connection": "ssh",
            #             }
            #         },
            #     ],
            # },
        ],
    }
    play_data = {
            "name": "mission name",    #mission name
            'gather_facts': "no",
            "hosts": "local",    #target host
            "vars": [
                {
                    # "application": "web-asp,web-asp-net,web-asp-net45",
                    # "create_test_file": "test1.txt",
                    "IPS": "192.168.56.0,192.168.56.1,192.168.56.2,192.168.56.3,192.168.56.4,192.168.56.5,192.168.56.6,192.168.56.7,192.168.56.8,192.168.56.9,192.168.56.10,192.168.56.11,192.168.56.12,192.168.56.13,192.168.56.14,192.168.56.15",
                }
            ],
            "tasks": [
                        # {
                        #     'action':{
                        #         'path':'C:/WINDOWS/TEMP/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #         'state':'directory',
                        #         'module':'win_file'
                        #     },
                        #     'name':'Create Mission Folder'
                        # },
                        # {
                        #     'action':{
                        #         'dest':'C:/WINDOWS/TEMP/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #         'src':'/data/devops_path/agenttemp/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #         'directory_mode':'yes',
                        #         'module':'win_copy'
                        #     },
                        #     'name':'Sync Mission Files'
                        # },
                        # {
                        #     u'action':{
                        #         u'patterns':[
                        #             u'1.txt.txt',
                        #             u'ababa.txt'
                        #         ],
                        #     'recurse':'no',
                        #     u'module':'win_find',
                        #     'paths':'C:/WINDOWS/TEMP/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/'
                        #     },
                        #     'register':'file_2_fetch',
                        #     u'name':u'11111'
                        # },
                        # {
                        #     u'action':{
                        #         'chdir':'C:/WINDOWS/TEMP/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #         u'args':u'hostname',
                        #         u'module':'win_shell'
                        #     },
                        #     u'name':u'hostname'
                        # },
                        # {
                        #     u'action':{
                        #         'chdir':'C:/WINDOWS/TEMP/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #         # u'args':u'hostname.ps1 dsadfsdfs rwerewrwerwe getos3.py',
                        #         'args':u'powershell hostname.ps1',
                        #         u'module':'win_shell'
                        #     },
                        #     u'name':u'hostnameps'
                        # },
                        # {
                        #     'action':{
                        #         'dest':'/data/devops_path/agenttemp/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #         'src':'{{ item.path }}',
                        #     'module': 'fetch',
                        #     'flat': 'yes'
                        #     },
                        #     'when':'file_2_fetch is defined',
                        #     'name':'sync Folder',
                        #     'with_items':'{{ file_2_fetch.files}}'
                        # }
                        {
                            u'action':{
                                u'path':u'/data/devops_path/agenttemp/1bc06765-560e-4833-a5e3-b50fcd51eea3/',
                                u'state':u'absent',
                                u'module':u'win_file',
                            },
                            u'name':u'1'
                        },
                        # {
                        #     'action':{
                        #         'module': 'win_copy',
                        #         # 'remote_src': 'yes',
                        #         'directory_mode': 'yes',
                        #         'src': '/data/devops_path/agenttemp/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #         'dest': 'C:/WINDOWS/TEMP/f3f682ef-af24-4b4f-9a5a-3e0e433406e0/',
                        #     },
                        #     'name':'2222',
                        # },
                        # {
                        #     'action':{
                        #         'dest':'C:/WINDOWS/TEMP/f3f682ef-af24-4b4f-9a5a-3e0e433406e0',
                        #         'src':'{{ item.path }}',
                        #         'module': 'win_copy',
                        #         'flat': 'yes',
                        #         },
                        #     # 'when':'file_2_fetch is defined',
                        #     'name':'sync Folder',
                        #     'with_items':'{{ file_2_fetch.files }}'
                        # },
                ],
            # "tasks": [
            #     # installing dependencies
            #     dict(name="ipconfig",
            #          action=dict(module="win_shell", args="New-Item C:/windows/temp/abc/0.txt -type file -force"),
            #          ),
            #
            #     # installing pip
            #
            #     dict(name="host",
            #          action=dict(module="win_shell", args="New-Item C:/windows/temp/abc/1.txt -type file -force")),
            #
            #     # installing docker-py; it is required for docker_container module
            #
            #     dict(name="hostname",
            #          action=dict(module="win_shell", args="New-Item C:/windows/temp/abc/2.txt -type file -force")),
            #
            #     dict(name="tasklist",
            #          action=dict(module="win_shell", args="New-Item C:/windows/temp/abc/3.txt -type file -force")),
            # ],
            # "handlers": [dict(name="ipconfig /all",
            #                action=dict(module="win_shell", args="ipconfig /all"))],

            }
    # {
    #         "name": "mission name2",    #mission name
    #         'gather_facts': "no",
    #         "hosts": "linux",    #target host
    #         "vars": [
    #             {
    #                 "application": "web-asp,web-asp-net,web-asp-net45",
    #                 "create_test_file": "test1.txt",
    #             }
    #         ],
    #         "tasks": [
    #             # installing dependencies
    #             dict(name="hostname",
    #                  action=dict(module="shell", args="hostname"),
    #                  ),
    #
    #             # installing pip
    #
    #             dict(name="ifconfig",
    #                  action=dict(module="shell", args="ifconfig")),
    #         ],
    #
    # },


    callback = MyCallBack()
    Inventory = MyInventory(inventory)
    play = MyPlay(play_data,Inventory)
    queue = TaskQueue(Inventory, callback)
    # host = '172.16.10.21'
    try:
        result = queue.TaskQueueManager.run(play.play)
        detail = queue.TaskQueueManager
        # pprint (vars(queue.TaskQueueManager._stdout_callback))
        # print queue.TaskQueueManager._stdout_callback.result
        # print json.dumps(queue.TaskQueueManager._stdout_callback.result)
    finally:
      # if queue.TaskQueueManager._stdout_callback.host_failed:
      #   pprint (vars(queue.TaskQueueManager._stdout_callback.host_failed[host]))
      # if queue.TaskQueueManager._stdout_callback.host_ok:
      #   pprint (vars(queue.TaskQueueManager._stdout_callback.host_ok[host]))
      # if queue.TaskQueueManager._stdout_callback.host_unreachable:
      #   pprint (vars(queue.TaskQueueManager._stdout_callback.host_unreachable[host]))
      if queue.TaskQueueManager is not None:
        queue.TaskQueueManager.cleanup()
