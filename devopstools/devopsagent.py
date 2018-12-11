#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import socket
import sys
import uuid
import json
import traceback
import struct
import select
import requests
import os
import copy
import threading, Queue, thread
import fcntl
import time
import yaml
import getopt
import signal
import hashlib
import chardet
import string
import subprocess
# from pprint import pprint
import re
import random


reload(sys)
sys.setdefaultencoding("utf-8")

def GetTime():
    t = time.strftime('%Y-%m-%d_%H:%M:%S',time.localtime(time.time()))
    return t

ROT13 = string.maketrans(\
         "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",\
         "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")

def rot13_encode(text):
    return string.translate(text, ROT13)

def GetHostname():
    child1 = subprocess.Popen(["hostname"], stdout=subprocess.PIPE)
    result,b = child1.communicate()
    hostname = result.split("\n")[0]
    return hostname

def GetDeployID(servername):
    md5 = hashlib.md5(GetTime()).hexdigest()
    hostname = GetHostname()
    id = md5[0] + md5[1] + hostname + "-" + servername + md5
    return rot13_encode(id)

#自定义异常类
class FileExists(Exception):
    def __init__(self):
        Exception.__init__(self)

#退出的类
class Watcher():
    def __init__(self):
        self.child = os.fork()
        if self.child == 0:
            return
        else:
            self.watch()

    def watch(self):
        try:
            os.wait()
        except KeyboardInterrupt:
            print "退出！"
            self.kill()
        sys.exit()

    def kill(self):
        try:
            os.kill(self.child, signal.SIGKILL)
        except OSError:
            pass

#写日志
class DevopsLog(object):
    def __init__(self,level=1,logpath=''):
        #level:1 debug,2 warn,3 error
        # print 'start'
        try:
            if not os.path.exists(logpath):
                os.makedirs(logpath)
            if level in [1,2,3]:
                self.level = level
                self.formatLen = 30#样式长度
                self.maxLogSize = 20*1024*1024
                # self.maxLogSize = 200*1024*1024
                # print self.level
                self.logpath = logpath
                self.initcode = 0

            else:
                print '日志级别非法'
                self.initcode = 1
        #Exception
        except Exception:
            print '日志参数有误：',traceback.format_exc()
            self.initcode = 1

    def Log(self,currentLevel,message):
        #处理日志内容
        try:
            if not message:
                return 0
            message = self.DealLog(message)
            if self.initcode == 0:
                if  currentLevel == 1 and self.level < 2:
                    return self.WriteLog("debug",message)
                elif currentLevel == 2 and self.level < 3:
                    return self.WriteLog("warn", message)
                elif currentLevel == 3 and self.level < 4:
                    return self.WriteLog("error", message)
                else:
                    return 0
        except Exception:
            print '写日志出现异常:', traceback.format_exc()
            return 0

    def WriteLog(self,currentLevel,message):
        # 判定文件是否存在，不存在则创建新的文件
        logFilePath = os.path.join(self.logpath, 'deploy.log')
        createTimeout = 300
        i = 1
        while i < createTimeout:#不断重写文件直到成功
            try:
                if not os.path.isfile(logFilePath):
                    with open(logFilePath, 'w') as f:
                        f.close()
                break
            except Exception:
                pass
            time.sleep(1)
            i += 1

        if i == createTimeout:
            print '创建文件超时（%d）！' % createTimeout
            return 0

        # 判断文件是否可写，可写则加文件锁，写入内容后释放,不可写则等待5s后再判断，超时则抛出写日志异常，然后退出
        writeTimeout = 300
        i = 1
        while i < writeTimeout:
            if os.access(logFilePath, os.W_OK):
                with open(logFilePath, 'a+') as f:
                    # print 'lock'
                    fcntl.flock(f, fcntl.LOCK_EX)
                    log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    if currentLevel == 'warn':
                        f.write(log_time + ' [' + currentLevel + ']  : ' + message + '\n')
                    else:
                        f.write(log_time + ' [' + currentLevel + '] : ' + message + '\n')
                    fcntl.flock(f, fcntl.LOCK_UN)
                    # print 'unlock'
                    #写完后如果文件大于指定大小则重命名
                    if os.path.getsize(logFilePath) > self.maxLogSize:
                        temp_time = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
                        os.rename(logFilePath,logFilePath + '.'+ temp_time)
                    break
            time.sleep(1)
            i += 1
        if i == createTimeout:
            print '写日志超时（%d）！' % writeTimeout
            return 0



    def DealLog(self,message):
        if isinstance(message,basestring):
            # print 'string:',message.replace('\n','\n'+' '* self.formatLen)
            return message.replace('\n','\n'+' '* self.formatLen)
        if isinstance(message,dict):
            message = self.PrettyDict(message)
            return message
        if isinstance(message,list):
            message = self.PrettyList(message)
            return message


    def PrettyDict(self,obj, ):
        return yaml.dump(obj).replace('\n','\n'+' '* self.formatLen)

    def PrettyList(self,dataList):
        newdataList = []
        for i in dataList: newdataList.append(str(i))
        split_str = '\n'+' '* self.formatLen
        return split_str.join(newdataList)

#创建线程
class MyThread(threading.Thread):

    def __init__(self, func, arg=None):
        super(MyThread, self).__init__()  #调用父类的构造函数
        self.func = func  #传入线程函数逻辑
        self.arg = arg

    def run(self):
        if self.arg:
            self.func(self.arg)
        else:
            self.func()

class AutoRegister(object):
    def __init__(self,id,url,msgqueue):
        self.id = id
        self.url = url
        self.msgqueue = msgqueue
        #初始化日志对象
        # self.logger = DevopsLog(loglevel, logpath)

    def Register(self):
        while True:
            try:
                data = {'id':self.id}
                ###push result
                headers = {
                    'Accept': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0',
                    'content-type': 'application/json'
                }
                data['methon'] = 'register'
                result = requests.post(self.url, headers=headers, json=json.dumps(data))
                re = result.json()
                if not re['code'] and re['data']:
                    return re['data']
                if re['code']:
                    print re['message']
                print "未能获取到注册信息。"
            except Exception as e:
                a = traceback.format_exc()
                print "连接失败: " + a
            print "60秒后重连"
            time.sleep(60)

    def UpdateStatus(self):
        while True:
            msg = self.msgqueue.get()
            if msg:
                try:
                    data = {'id':self.id}
                    data['msg'] = msg
                    ###push result
                    headers = {
                        'Accept': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0',
                        'content-type': 'application/json'
                    }
                    data['methon'] = 'status'
                    result = requests.post(self.url, headers=headers, json=json.dumps(data))
                    re = result.json()
                    if re['code']:
                        print "未能同步信息。"
                except Exception as e:
                    a = traceback.format_exc()
                    print "连接失败: " + a
            time.sleep(60)

class DevopsWorker(object):
    def __init__(self,id,bind=None,weburl=None,token=None,worktype=None,serverurl=None,arg=None, loglevel=None, logpath=None, msgqueue=None):
        self.bind = bind
        self.weburl = weburl
        self.token = token
        self.workqueue = Queue.Queue()
        self.resultqueue = Queue.Queue()
        self.time = None
        self.log = None
        self.workinglist = []
        self.worktype = worktype
        self.serverurl = serverurl
        self.arg = arg
        self.structpack = '1024s1024s128sI64sI'
        self.id = id
        self.proxyandresult = {}
        self.msgqueue = msgqueue

        #初始化日志对象
        self.logger = DevopsLog(loglevel, logpath)

    def WorkerNameToWork(self,name):
        print "WorkerNameToWork","----",name
        self.logger.Log(1, "WorkerNameToWork----" + name)
        try:
            if name == 'GetMission':
                #建立获取任务的线程
                threadname = 'GetMission_' + self.GetTime()
                thread = MyThread(self.GetMission)
                thread.setName(threadname)
                thread.start()  #线程开始处理任务

            if name.find('StartBindTo') >=0 :
                #建立监听线程
                bindinfo = name.split("To")[1]
                threadname = 'StartBindTo' + bindinfo + "_" + self.GetTime()
                thread = MyThread(self.StartBind,bindinfo)
                thread.setName(threadname)
                thread.start()  #线程开始处理任务

            if name == 'PushMissionResult':
                #建立监听线程
                threadname = 'PushMissionResult_' + self.GetTime()
                thread = MyThread(self.PushMissionResult)
                thread.setName(threadname)
                thread.start()  #线程开始处理任务

            if name == 'ServerWorker':
                #建立监听线程
                threadname = 'ServerWorker_' + self.GetTime()
                thread = MyThread(self.ServerWorker)
                thread.setName(threadname)
                thread.start()  #线程开始处理任务

            if name == 'ProxyResultToServer':
                #建立监听线程
                threadname = 'ProxyResultToServer_' + self.GetTime()
                thread = MyThread(self.ProxyResultToServer)
                thread.setName(threadname)
                thread.start()  #线程开始处理任务

            if name == 'ProxyWorker':
                #建立监听线程
                threadname = 'ProxyWorker_' + self.GetTime()
                thread = MyThread(self.ProxyWorker)
                thread.setName(threadname)
                thread.start()  #线程开始处理任务

        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            # traceback.format_exc()

    def Guard(self):
        self.workinglist = []
        if self.worktype == 'server':
            self.workinglist = [
                    'GetMission',
                    'PushMissionResult',
                    'ServerWorker',
                ]
            for bind in self.bind:
                self.workinglist.append('StartBindTo' + bind)
        elif self.worktype == 'proxy':
            self.workinglist = [
                    'ProxyResultToServer',
                    'ProxyWorker',
                ]
            for bind in self.bind:
                self.workinglist.append('StartBindTo' + bind)
        if not self.workinglist:
            print "请定义工作模式"
            self.logger.Log(3, "请定义工作模式")
            return

        while True:
            threadnamelist = [thread.getName().split("_")[0] for thread in threading.enumerate()]
            # print "存活线程:" + ",".join(threadnamelist)
            self.logger.Log(1, "存活线程:" + ",".join(threadnamelist))
            okflag = True
            missinglist = []
            for workername in self.workinglist:
                if not workername in threadnamelist:
                    okflag = False
                    missinglist.append(workername)
                    self.WorkerNameToWork(workername)
            if self.msgqueue:
                if okflag:
                    self.msgqueue.put('工作正常')
                else:
                    self.msgqueue.put('缺少线程' + ",".join(missinglist))
            time.sleep(5)

    def GetTime(self):
        self.time = time.strftime('%Y-%m-%d_%H:%M:%S',time.localtime(time.time()))
        return self.time

    def DivList(self,ls,n):
        try:
            ####功能：将list对象N等分
            if not isinstance(ls,list) or not isinstance(n,int):
                return []
            ls_return = []
            lslen = len(ls)
            divlen = lslen/n
            leftcount = lslen%n
            ls_return = [ls[i:i+divlen] for i in range(0,lslen-leftcount,divlen)]
            if leftcount:
                ls_left = ls_return.pop()
                ls_left.extend(ls[-int(leftcount):])
                ls_return.append(ls_left)
            return ls_return
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            # traceback.format_exc()
            # print a
            return []

    def FunctionDefined(self,f):
        try:
            return (" " + f).zfill(40)
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            # traceback.format_exc()
            return " ".zfill(40)

    #数据拆分与接收
    def SendData(self,c, data):
        # Prefix each message with a 4-byte length (network byte order)
        data = struct.pack('>I', len(data)) + data
        try:
            c.sendall(data)
        except socket.error, e:
            pass

    def RecvAll(self,c, n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = b''
        try:
            while len(data) < n:
                packet = c.recv(n - len(data))
                if not packet:
                    return None
                data += packet
        except socket.error, e:
            return None
        return data

    def RecvData(self,c):
        # Read message length and unpack it into an integer
        raw_msglen = self.RecvAll(c, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return self.RecvAll(c, msglen)

    def GetFileMD5(self, filepath):
        code = ''
        try:
            '''
            check md5
            :param missionfile:
            :return: file md5
            '''
            if not os.path.isfile(filepath):
                return
            myhash = hashlib.md5()
            f = file(filepath, 'rb')
            while True:
                b = f.read(8096)
                if not b:
                    break
                myhash.update(b)
            f.close()
            # print '最新文件的md5:',myhash.hexdigest()
            code = myhash.hexdigest()
        except Exception as e:
            a = traceback.format_exc()
            print a
        finally:
            return code

    def GetMission(self):
        # print "GetMission"
        while True:
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0',
                'content-type': 'application/json'
            }
            data = {'methon':'getmission', 'id':self.id}
            try:
                r = requests.post(self.weburl, headers=headers,json=json.dumps(data))
                if not r.json()['code']:
                    missionlist = json.loads(r.json()['data'])
                    # self.logger.Log(1, missionlist)
                    for mission in missionlist:
                        self.workqueue.put(mission)
            except requests.ConnectionError:
                print '网站获取待执行任务的api不可用'
                self.logger.Log(3, '网站获取待执行任务的api不可用')
            except Exception as e:
                a = traceback.format_exc()
                self.logger.Log(3, a)
                print a
                # traceback.format_exc()
            finally:
                interval = 60
                if self.arg.has_key('GetMissionInterval'):
                    interval = self.arg['GetMissionInterval']
                time.sleep(interval)

    def PushMissionResult(self):
        # print "PushMissionResult"
        while True:
            data = self.resultqueue.get()
            if data:
                ###push result
                headers = {
                    'Accept': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0',
                    'content-type': 'application/json'
                }
                data['id'] = self.id
                data['methon'] = 'pushmissionresult'
                result = requests.post(self.weburl, headers=headers, json=json.dumps(data))

    def GetFile(self,missionid,getfilename,missionpath,savefilename=None):
        ###push result
        try:
            data = {}
            data['id'] = self.id
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0',
                'content-type': 'application/json'
            }
            data['methon'] = 'file'
            data['filename'] = getfilename
            data['missionid'] = missionid
            result = requests.post(self.weburl, headers=headers, json=json.dumps(data), stream=True)
            if result.status_code == 200:
                d = result.headers['content-disposition']
                fname = savefilename if savefilename else re.findall("filename=(.+)", d)[0] if re.findall("filename=(.+)", d) else data['filename']
                if self.CheckMissionPath(missionpath)[0]:
                    with open(os.path.join(missionpath,fname),'w') as f:
                        for chunk in result.iter_content(chunk_size=512):
                            if chunk:
                                f.write(chunk)
                    return True
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            print a
            return False
        return False

    def CheckMissionPath(self,path):
        i = 0
        while i < 3:
            i = i + 1
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                    break
                except OSError:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
                    print a
                except Exception as e:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
                    print a
                finally:
                    time.sleep(1)
            else:
                break
        if os.path.exists(path):
            return True,""
        return False,path + '无法访问！'

    def ProxyResultToServer(self):
        # print "PushMissionResult"
        while True:
            data = self.resultqueue.get()
            if data:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((self.serverurl.split(":")[0],int(self.serverurl.split(":")[1])))
                    s.send(self.FunctionDefined('missionresult'))
                    self.SendData(s, json.dumps(data))
                    s.close()
                except Exception as e:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
                    # traceback.format_exc()
                    SocketReconnectInterval = 10
                    if self.arg.has_key('SocketReconnectInterval'):
                        SocketReconnectInterval = self.arg['SocketReconnectInterval']
                    print "回传任务结果出错服务端" + self.serverurl + "将在" + str(SocketReconnectInterval) + "秒后重新尝试连接"
                    self.logger.Log(3, "回传任务结果出错服务端" + self.serverurl + "将在" + str(SocketReconnectInterval) + "秒后重新尝试连接")
                    time.sleep(SocketReconnectInterval)
                    self.resultqueue.put(data)

    def ProxyWorkModuleAnsible(self,data,missionid):
        try:
            import ansibleV20API as ansible
            #脚本执行环境
            script_evr = {
                'sh': 'bash ',
                'py': 'python ',
                'ps1': '.\\',
                'vbs': 'cscript ',
                'bat': None,
            }
            #重组inventory
            data['inventory'] = {}
            data['inventory']['groups'] = []
            data['hostnametoip'] = {}
            existgroup = []
            for i in data.pop('target'):
                if not i['groupname'] in existgroup:
                    existgroup.append(i['groupname'])
                    data['inventory']['groups'].append({'groupname':i['groupname'],'hosts':[]})
                if i['hosts'].has_key('ip'):
                    if i['hosts']['ip']:
                        ip = i['hosts'].pop('ip').pop()
                        data['hostnametoip'][i['hosts']['hostname']] = ip
                        i['hosts']['hostname'] = ip
                credential = i['hosts'].pop('credential')
                if credential:
                    try:
                        if i['groupname'].lower() == 'windows':
                            i['hosts']['variable'] = {
                                "ansible_user": credential['username'],
                                "ansible_password": credential['password'],
                                "ansible_port": "5986",
                                "ansible_connection": "winrm",
                                "ansible_winrm_server_cert_validation":"ignore",
                            }
                        elif i['groupname'].lower() == 'linux':
                            i['hosts']['variable'] = {
                                "ansible_user": credential['username'],
                                "ansible_password": credential['password'],
                                "ansible_port": "22",
                                "ansible_connection": "ssh",
                                "ansible_ssh_common_args" : "-o StrictHostKeyChecking=no",
                            }
                        elif i['groupname'].lower() == 'local':
                            i['hosts']['variable'] = {
                                "ansible_user": self.arg['localaccount']['user'],
                                "ansible_password": self.arg['localaccount']['password'],
                                "ansible_port": "22",
                                "ansible_connection": "ssh",
                                "ansible_ssh_common_args" : "-o StrictHostKeyChecking=no",
                            }
                        elif i['groupname'].lower() == 'custom':
                            i['hosts']['variable'] = json.loads(credential)
                    except Exception as e:
                        a = traceback.format_exc()
                        self.logger.Log(3, a)
                for g in data['inventory']['groups']:
                    if g['groupname'] == i['groupname']:
                        g['hosts'].append(i['hosts'])
                        break
            data['play']['hosts'] = existgroup[0]

            module_file = 'copy'
            module_path = 'file'
            module_find = 'find'
            module_shell = 'shell'
            if data['play']['hosts'].lower() == 'windows':
                module_file = 'win_copy'
                module_path = 'win_file'
                module_find = 'win_find'
                module_shell = 'win_shell'

            #获取目标机器保存文件路径
            localtemp = ""
            if data['play']['hosts'].lower() == 'local':
                localtemp = self.arg['tempfilepath']
            else:
                for path in self.arg['filepath']:
                    if path[0].lower() == data['play']['hosts'].lower():
                        localtemp = path[1]
                        break
            if not localtemp:
                self.logger.Log(3, "没有配置目标机器保存文件的目录，无法保存文件！")
                raise Exception("没有配置目标机器保存文件的目录，无法保存文件！")
            localtemp = os.path.join(localtemp,missionid + "-" + data['pathid'])  + "/"

            #获取proxy保存文件路径
            if not self.arg.has_key('tempfilepath'):
                self.logger.Log(3, "没有配置保存文件的目录，无法保存文件！")
                raise Exception("没有配置保存文件的目录，无法保存文件！")
            missionpath = os.path.join(self.arg['tempfilepath'],missionid + "-" + data['pathid']) + "/"
            if not self.CheckMissionPath(missionpath)[0]:
                raise Exception("没有配置保存文件的目录，无法保存文件！")

            #重组play
            fetchtasklist = []
            for task in data['play']['tasks']:
                if task['action']['module'] == 'find':
                    task['action']['module'] = module_find
                    task['action']['paths'] = localtemp
                    task['action']['recurse'] = 'no'
                    task['register'] = 'file_2_fetch'
                    fetchtask = {
                                    'action':{
                                        'src':'{{ item.path }}',
                                        'dest': missionpath,
                                        'flat':'yes',
                                        'module':'fetch',
                                        },
                                    'name':'Sync Folder',
                                    'with_items': "{{ file_2_fetch.files }}",
                                    'when': 'file_2_fetch is defined',
                                }
                    fetchtasklist.append(fetchtask)
                if task['action']['module'] == 'template':
                    task['action']['src'] = os.path.join(missionpath,task['action']['src'])
                    task['action']['dest'] = os.path.join(localtemp,task['action']['dest'])
                if task['action']['module'] == 'shell':
                    task['action']['module'] = module_shell
                    task['action']['chdir'] = localtemp
                    try:
                        suffix = task['action']['args'].split(" ")[0].split(".")[-1]
                        if suffix:
                            if script_evr[suffix]:
                                task['action']['args'] = script_evr[suffix] + task['action']['args']
                    except Exception as e:
                        pass


            data['play']['tasks'].extend(fetchtasklist)

            #删除任务目录
            removemissionfolder = {
                            'action':{
                                'path': localtemp,
                                'state': 'absent',
                                'module': module_path,
                                },
                            'name':'Del Mission Folder',
                        }
            data['play']['tasks'].append(removemissionfolder)

            data['play']['tasks'].insert(0,{'action': {
                'module':module_file,
                'directory_mode': 'yes',
                'src': missionpath,
                'dest': localtemp,
            },
                'name': 'Sync Mission Files',
            })
            #创建任务目录
            data['play']['tasks'].insert(0,{'action': {
                'module': module_path,
                'path': localtemp,
                'state': 'directory',
            },
                'name': 'Create Mission Folder',
            })
            data['tempfolder'] = missionpath
            # self.logger.Log(1, data)
            #ansible开始处理
            callback = ansible.MyCallBack()
            job_inventory = ansible.MyInventory(data['inventory'])
            job_play = ansible.MyPlay(data['play'], job_inventory)
            job = ansible.TaskQueue(job_inventory, callback).TaskQueueManager
            do_job = job.run(job_play.play)
            job_result = job._stdout_callback.result
            result = True
            data['iptohostname'] = {v: k for k, v in data['hostnametoip'].items()}

            flag = False
            for r in job_result.keys():
                if flag:
                    break
                for c in job_result[r]:
                    if not c['code'].lower() == 'ok':
                        result = False
                        flag = True
                        break
            for r in job_result.keys():
                if data['iptohostname'].has_key(r):
                    job_result[data['iptohostname'][r]] = job_result.pop(r)

            data['result'] = result
            data['detail'] = job_result

            return data
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            print a
            data['result'] = False
            data['detail'] = {"Total": [{"code": "FAILED", "command": "None", "result": {"task": data['mission']['missionname'], "stdout": "Mission Failed, please check more detail with admin!"}}]}
            return data

    def ErrorResult(self,resultid,msg=None):
        try:
            data = {}
            if not msg:
                msg = "Mission Failed, please check more detail with admin!"
            data['resultid'] = resultid
            data['result'] = False
            data['detail'] = {"Total": [{"code": "FAILED", "command": "None", "result": {"stdout": msg}}]}
            self.resultqueue.put(data)
            return True
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            return False

    def RemoveMissionFolder(self,path):
        try:
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            if os.path.exists(path):
                os.rmdir(path)
            return True,None
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            print a
            return False,a

    def CheckResult(self,data):
        try:
            self.proxyandresult[data['mission']['id']][data['proxyid']] = data
            missionresult = self.proxyandresult[data['mission']['id']]
            for v in missionresult.values():
                if not v:
                    return False
            result = {'pathid': missionresult['pathid'], 'missionid':data['mission']['id'], 'resultid': missionresult['resultid'], 'result':True, 'detail':{}}
            for k in missionresult.keys():
                if k == 'resultid' or k == 'pathid':
                    continue
                r = missionresult[k]
                if not r['result']:
                    result['result'] = False
                try:
                    if r.has_key('detail'):
                        for key in r['detail'].keys():
                            if result['detail'].has_key(key):
                                result['detail'][key].extend(r['detail'][key])
                            else:
                                result['detail'][key] = r['detail'][key]
                except Exception as e:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
                    pass
            self.RemoveMissionFolder(os.path.join(self.arg['tempfilepath'],result['missionid'] + "-" + result['pathid']) + "/")
            self.resultqueue.put(result)
            return True
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            print a
            return False


    def ListMision(self,missionlist,data):
        missionlist.insert(0,data)
        if data['partner']:
            for x in data['partner']:
                missionlist = self.ListMision(missionlist,x)
        return missionlist


    def ProxyWorkModule(self,data):
        result = None
        pushresult = None
        missionid = str(data['mission']['id'])
        missionlist = self.ListMision([],data)
        results = []
        for m in missionlist:
            m['pathid'] = data['pathid']
            if m['module'] == 'ansible':
                result = self.ProxyWorkModuleAnsible(m,missionid)
                if result:
                    results.append(result)
                    try:
                        if not result['result']:
                            break
                    except Exception as e:
                        a = traceback.format_exc()
                        self.logger.Log(3, a)
        if results:
            pushresult = {'mission': {'id': missionid }, 'detail': {}, 'tempfolder': [],}
            for r in results:
                pushresult['result'] = r['result']
                if r.has_key('tempfolder'):
                    pushresult['tempfolder'].append(r['tempfolder'])
                try:
                    if r.has_key('detail'):
                        for key in r['detail'].keys():
                            if pushresult['detail'].has_key(key):
                                pushresult['detail'][key].extend(r['detail'][key])
                            else:
                                pushresult['detail'][key] = r['detail'][key]
                except Exception as e:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
        if pushresult:
            pushresult['proxyid'] = self.id
            tempfolder = pushresult.pop('tempfolder')
            self.resultqueue.put(pushresult)
            for f in tempfolder:
                self.RemoveMissionFolder(f)
        threading.currentThread()._Thread__stop()


    # def BindPort(self):
    #     # print "BindPort"
    #     for bindinfo in self.bind:
    #         #建立监听线程
    #         threadname = 'StartBindTo' + bindinfo + "_" + self.GetTime()
    #         thread = MyThread(self.StartBind,bindinfo)
    #         thread.setName(threadname)
    #         thread.start()  #线程开始处理任务

    def StartBind(self,bindinfo):
        # print "StartBind"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "Socket created"
        self.logger.Log(1, "Socket created")

        #Bind socket to local host and port
        try:
            s.bind((bindinfo.split(":")[0], int(bindinfo.split(":")[1])))
        except socket.error , msg:
            print "Bind failed. Error Code : " + str(msg[0]) + " Message " + msg[1] + "-------for------" + bindinfo
            self.logger.Log(3, "Bind failed. Error Code : " + str(msg[0]) + " Message " + msg[1] + "-------for------" + bindinfo)
            sys.exit()

        print bindinfo + " bind complete"
        self.logger.Log(1, bindinfo + " bind complete")
        #Start listening on socket
        s.listen(10)
        print bindinfo + " now listening"
        self.logger.Log(1, bindinfo + " now listening")
        while True:
            #wait to accept a connection - blocking call
            newconn, addr = s.accept()
            print "Connected with " + addr[0] + ":" + str(addr[1])
            self.logger.Log(1, bindinfo + " now listening")
            #建立通讯线程
            threadname = 'SocketWorker_' + self.GetTime()
            thread = MyThread(self.SocketWorker,newconn)
            thread.setName(threadname)
            thread.start()  #线程开始处理任务

        s.close()
        threading.currentThread()._Thread__stop()

    def SocketWorker(self,connection):
        # print "SocketWorker"

        data = connection.recv(40)
        data = data.split(" ")[1]
        try:
            if data == 'file':
                try:
                    if not self.arg.has_key('tempfilepath'):
                        self.logger.Log(3, "没有配置保存文件的目录，无法保存文件！")
                        raise Exception("没有配置保存文件的目录，无法保存文件！")
                    FILEINFO_SIZE = struct.calcsize(self.structpack)
                    fhead = connection.recv(FILEINFO_SIZE)
                    missionid, filename, filecode, size, pathid, partsize = struct.unpack(self.structpack, fhead)
                    missionid = missionid.strip('\00')
                    pathid = pathid.strip('\00')
                    missionpath = os.path.join(self.arg['tempfilepath'],missionid + "-" + pathid) + "/"
                    if not self.CheckMissionPath(missionpath)[0]:
                        raise Exception("没有配置保存文件的目录，无法保存文件！")
                    filename = os.path.join(missionpath,filename.strip('\00'))
                    filecode = filecode.strip('\00')
                    if os.path.exists(filename):
                        if self.GetFileMD5(filename) == filecode:
                            raise FileExists()
                        os.remove(filename)
                    temp_time = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())) + str(uuid.uuid1())
                    temp_filename = os.path.join(missionpath,'temp'+ temp_time)
                    current_size = 0
                    buffer = b""
                    f = open(temp_filename,'wb+')
                    while current_size < size:
                        try:
                            data = connection.recv(partsize)
                            if not data:
                                break
                            if len(data) + current_size > size:
                                data = data[:size-current_size] # trim additional data
                            buffer += data
                            f.write(data)
                            f.flush()
                            current_size += len(data)
                        except Exception as e:
                            a = traceback.format_exc()
                            self.logger.Log(3, a)
                            # traceback.format_exc()
                    f.close
                    if self.GetFileMD5(temp_filename) == filecode:
                        os.rename(temp_filename, filename)
                except FileExists:
                    self.logger.Log(1, "文件：" + filename + " 已存在，不重传！")
                    # print "文件：" + filename + " 已存在，不重传！"
                    pass
                except Exception as e:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
                    pass
                finally:
                    connection.close()
            elif data == 'mission':
                data = self.RecvData(connection)
                self.workqueue.put(json.loads(data))
                connection.close()
            elif data == 'missionresult':
                data = self.RecvData(connection)
                self.CheckResult(json.loads(data))
                connection.close()
                pass
            else:
                connection.close()
        except Exception as e:
            # traceback.format_exc()
            a = traceback.format_exc()
            self.logger.Log(3, a)
        finally:
            threading.currentThread()._Thread__stop()

    def SendMission(self,(data,proxy)):
        # print "SendMission"
        if data['file']:
            #建立发送文件线程
            sendfileresult = self.SendFile(data,proxy)
            if not sendfileresult:
                threading.currentThread()._Thread__stop()
                return

        #server发任务到proxy，目前就一次，而且故障的话没有输出报错
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((proxy.split(":")[0],int(proxy.split(":")[1])))
            s.send(self.FunctionDefined('mission'))
            self.SendData(s, json.dumps(data))
            s.close()
            threading.currentThread()._Thread__stop()
            return
        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            print a
            # traceback.format_exc()
            SocketReconnectInterval = 10
            if self.arg.has_key('SocketReconnectInterval'):
                SocketReconnectInterval = self.arg['SocketReconnectInterval']
            print "发送任务信息，连接不上代理" + proxy + "将在" + str(SocketReconnectInterval) + "秒后重新尝试连接"
            self.logger.Log(3, "发送任务信息，连接不上代理" + proxy + "将在" + str(SocketReconnectInterval) + "秒后重新尝试连接")
            time.sleep(SocketReconnectInterval)
            self.SendMission(arg)

    def SendFile(self,data,proxy):
        # print "SendFile"
        try:
            missionpath = os.path.join(self.arg['tempfilepath'],str(data['mission']['id']) + "-" + data['pathid']) + "/"
            from datetime import datetime as d
            starttime = d.now()
            for file in data['file']:
                endtime = d.now()
                if (endtime - starttime).seconds > self.arg['TransferFileTimeout']:
                    self.ErrorResult(data['resultid'], '服务端下载文件超时，退出！')
                    return False
                filename = str(file['templatename']) if file.has_key('templatename') else str(file['filename'])
                downloadfilename = str(file['filerealname'])
                filecode = str(file['fileidcode'])
                filepath = os.path.join(missionpath,filename)
                #先下载文件
                i = 0
                try:
                    while i < 3:
                        i = i + 1
                        #下载文件
                        if not self.GetFile(str(data['mission']['id']),downloadfilename,missionpath,filename):
                            time.sleep(60)
                            continue
                        #校验文件MD5
                        if self.GetFileMD5(filepath) == filecode:
                            break
                        time.sleep(30)
                    if i >=3:
                        self.ErrorResult(data['resultid'],'无法下载文件' + filename)
                        threading.currentThread()._Thread__stop()
                        return False
                except Exception as e:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
                    print a
                    self.ErrorResult(data['resultid'], '服务端处理任务失败，退出！')
                    return False

            for file in data['file']:
                filename = str(file['templatename']) if file.has_key('templatename') else str(file['filename'])
                filepath = os.path.join(missionpath,filename)
                i = 0
                while i < 3:
                    i = i + 1
                    #连接代理
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((proxy.split(":")[0],int(proxy.split(":")[1])))
                    s.send(self.FunctionDefined('file'))
                    try:
                        #传输文件
                        filesize = os.stat(filepath).st_size
                        if filesize / (1024*1024*1024) > 0:
                            partsize = 40960
                        elif filesize / (1024*1024*10) > 0:
                            partsize = 4096
                        else:
                            partsize = 1024
                        fhead = struct.pack(self.structpack, str(data['mission']['id']), filename, str(file['fileidcode']), filesize, data['pathid'], partsize)  # 按照规则进行打包
                        s.send(fhead)  # 发送文件基本信息数据
                        current_size = 0
                        with open(filepath, 'r') as infile:
                            d = infile.read(partsize)
                            while d:
                                current_size = len(d) + current_size
                                s.send(d)
                                d = infile.read(partsize)
                        s.close()
                        break
                    except Exception as e:
                        a = traceback.format_exc()
                        self.logger.Log(3, a)
                        print a
                        SocketReconnectInterval = 10
                        if self.arg.has_key('SocketReconnectInterval'):
                            SocketReconnectInterval = self.arg['SocketReconnectInterval']
                        print "发送任务文件，连接不上代理" + proxy + "将在" + str(SocketReconnectInterval) + "秒后重新尝试连接"
                        self.logger.Log(3, "发送任务文件，连接不上代理" + proxy + "将在" + str(SocketReconnectInterval) + "秒后重新尝试连接")
                        time.sleep(SocketReconnectInterval)
                        continue
                if i >=3:
                    self.ErrorResult(data['resultid'],'服务端到代理传输文件失败，退出！')
                    return False

            return True

        except Exception as e:
            a = traceback.format_exc()
            self.logger.Log(3, a)
            print a
            self.ErrorResult(data['resultid'],'服务端处理任务失败，退出！')
            threading.currentThread()._Thread__stop()
            return False

        # self.SendMission(arg)



    def ServerWorker(self):
        # print "ServerWorker"
        while True:
            data = self.workqueue.get()
            if data:
                try:
                    if data['proxy']:
                        _n = "%d" % (time.time() * 1000)
                        _f = time.strftime("%Y%m%d", time.localtime())
                        data['pathid'] =  _f + _n + str(random.randint(1, 10))
                        self.proxyandresult[data['mission']['id']] = {'resultid':data['resultid'], 'pathid':data['pathid']}
                        proxycount = len(data['proxy'])
                        targetlist = self.DivList(data['target'],proxycount)
                        for proxy in data['proxy']:
                            if targetlist:
                                data['target'] = targetlist.pop()
                                self.proxyandresult[data['mission']['id']][proxy['id']] = None
                                #建立发送任务线程

                                threadname = 'SendMission_' + proxy['listener'] + "_" + self.GetTime()
                                thread = MyThread(self.SendMission,(data,proxy['listener']))
                                thread.setName(threadname)
                                thread.start()  #线程开始处理任务

                    else:
                        self.ErrorResult(data['resultid'],'没有选择发布代理，任务将无法发布，直接结束！')
                except Exception as e:
                    a = traceback.format_exc()
                    self.logger.Log(3, a)
                    print a
                    self.ErrorResult(data['resultid'])

    def ProxyWorker(self):
        # print "ProxyWorker"
        print "start ProxyWorker"
        while True:
            data = self.workqueue.get()
            if data:
                if data.has_key('server'):
                    self.serverurl = data['server']['listener']
                    threadname = 'ProxyWorkModule_' + str(data['mission']['id']) + "_" + self.GetTime()
                    thread = MyThread(self.ProxyWorkModule,(data))
                    thread.setName(threadname)
                    thread.start()  #线程开始处理任务

        print "end ProxyWorker"

    def Run(self):
        print "run"
        #建立守护线程
        threadname = 'Guard_' + self.GetTime()
        thread = MyThread(self.Guard)
        thread.setName(threadname)
        thread.start()  #线程开始处理任务



if __name__ == "__main__":

    nameandids = []
    name = None
    id = None
    config = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "n:l:d", ["name", "url","debug"])
    except getopt.GetoptError:
        pass
        # print help information and exit:

    for o, a in opts:
        if o in ("-n", "--name"):
            name = a
        if o in ("-l", "--url"):
            url = a
        if o in ("-d", "--debug"):
            # 监控退出指令
            Watcher()


    if name:
        if os.path.exists('.deployconfig'):
            with open('.deployconfig','r') as f:
                nameandids = f.readlines()
        for nameandid in nameandids:
            if name == nameandid.split(",")[0]:
                id = nameandid.split(",")[1].replace("\n", "")
                break
    else:
        print "Useage: agent.py -n name -l url"
        sys.exit()

    if not id:
        id = GetDeployID(name)
        if os.path.exists('.deployconfig'):
            with open('.deployconfig','a') as f:
                f.write(name + "," + id + "\n")
        else:
            with open('.deployconfig','w') as f:
                f.write(name + "," + id + "\n")

    if id:
        #定时连接网站更新工作状态
        msgqueue = Queue.Queue()
        a = AutoRegister(id,url,msgqueue)
        threadname = 'UpdateStatus_' + GetTime()
        thread = MyThread(a.UpdateStatus)
        thread.setName(threadname)
        thread.start()  #线程开始处理任务



        while True:
            config = json.loads(a.Register())
            if config:
                arg = {}
                bind = [str(config['serverip']) + ":" + str(config['serverport'])]

                #附加的参数
                try:
                    arg['GetMissionInterval'] = config['getmissioninterval']
                except Exception as e:
                    arg['GetMissionInterval'] = None

                try:
                    arg['SocketReconnectInterval'] = config['socketreconnectinterval']
                except Exception as e:
                    arg['SocketReconnectInterval'] = None


                #写死了目标机器的临时目录
                try:
                    arg['filepath'] = [
                        ("windows","C:/WINDOWS/TEMP/"),
                        ("linux","/tmp/"),
                        ("custom","/tmp/"),
                    ]
                except Exception as e:
                    arg['filepath'] = None



                try:
                    arg['tempfilepath'] = config['tempfilepath']
                    tempfile = os.path.join(arg['tempfilepath'],str(uuid.uuid1()))
                    with open(tempfile,'w') as f:
                        f.write('test')
                    os.remove(tempfile)
                except Exception as e:
                    print e
                    msgqueue.put(config['tempfilepath'] + "无法正常写入！")
                    time.sleep(60)
                    continue

                try:
                    arg['localaccount'] = {'user':config['localaccount_username'],'password':config['localaccount_password'],}
                except Exception as e:
                    arg['localaccount'] = None

                try:
                    arg['TransferFileTimeout'] = config['transferfiletimeout']
                except Exception as e:
                    arg['TransferFileTimeout'] = None

                try:
                    token = config['id']
                except Exception as e:
                    token = None

                try:
                    loglevel = config['loglevel']
                    if not int(loglevel) in [1,2,3]:
                        msgqueue.put("错误等级只能是1,2,3")
                        time.sleep(60)
                        continue
                except Exception as e:
                    msgqueue.put(str(e))
                    time.sleep(60)
                    continue

                try:
                    logpath = config['logpath']
                    tempfile = os.path.join(logpath,str(uuid.uuid1()))
                    with open(tempfile,'w') as f:
                        f.write('test')
                    os.remove(tempfile)
                except Exception as e:
                    msgqueue.put(config['logpath'] + "无法正常写入！")
                    time.sleep(60)
                    continue

                break

            else:
                print "未能获取到注册信息，退出。"
                sys.exit()

        configinfo = {
            'id': id[-32:],
            'bind': bind,
            'weburl': url,
            'token': token,
            'worktype': config['servertype'],
            'arg': arg,
            'loglevel': loglevel,
            'logpath': logpath,
            'msgqueue': msgqueue,
        }

        # print configinfo
        # sys.exit()
        server = DevopsWorker(**configinfo)

        server.Run()
#
