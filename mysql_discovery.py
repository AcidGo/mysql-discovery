# -*- conding: utf-8 -*-

# Author: AcidGo

import json
import os
import platform
import subprocess
from ConfigParser import SafeConfigParser

import psutil

class Result(object):
    def __init__(self):
        self._res = dict()

    def get_res(self):
        return self._res

    def set_val(self, typ, key, val):
        if typ not in self._res:
            self._res[typ] = {}
        self._res[typ].update({key: val})

    def get_val(self, typ, key):
        if typ not in self._res or key not in self._res[typ]:
            return None
        return self._res[typ][key]

    def set_typ(self, typ, dct):
        if typ not in self._res:
            self._res[typ] = {}
        self._res[typ] = dct

    def get_typ(self, typ):
        return self._res.get(typ, {})

    def resset(self):
        self._res = dict()

class MySQLDiscovery(object):
    def __init__(self, pid):
        self.pid = int(pid)
        self.res = Result()
        self._is_docker = False

        if not self.pid and self.pid < 1:
            raise Exception("")

        self._docker_process()

    def get_res(self):
        return self.res

    def _docker_process(self):
        if LinuxLib.is_docker_proc(self.pid):
            self._is_docker = True
            self.res.set_val("__inner__", "is_docker", True)

    def scan_mysql_os(self):
        if self._is_docker:
            return 

        typ = "OS"
        self.res.set_val(typ, "system", platform.system())
        self.res.set_val(typ, "platform", platform.platform())

    def scan_mysql_base(self):
        if self._is_docker:
            return 

        typ = "Base"
        conf_path = MySQLLib.find_mysqld_confpath(self.pid)
        exec_path = MySQLLib.find_mysqld_execpath(self.pid)
        mysqld_version = MySQLLib.get_mysqld_version(exec_path)

        self.res.set_val(typ, "conf_path", conf_path)
        self.res.set_val(typ, "exec_path", exec_path)
        self.res.set_val(typ, "mysqld_version", mysqld_version)

    def scan_mysql_conf(self):
        if self._is_docker:
            return 

        typ = "Conf"
        conf_path = MySQLLib.find_mysqld_confpath(self.pid)

        conf_dict = MySQLLib.get_mysqld_confargs(conf_path)
        cmdargs_dict = MySQLLib.get_mysqld_cmdargs(self.pid)
        conf_dict.update(cmdargs_dict)
        self.res.set_typ(typ, conf_dict)

class LinuxLib(object):
    @staticmethod
    def _get_proctype_by_pid(proctype, pid):
        prefix = "/proc/{!s}".format(pid)
        if proctype == "cwd":
            return os.readlink(prefix + "/cwd")
        if proctype == "exe":
            return os.readlink(prefix + "/exe")
        raise Exception("not support {!s} for the function".format(proctype))

    @staticmethod
    def get_cwd_by_pid(pid):
        return LinuxLib._get_proctype_by_pid("cwd", pid)

    @staticmethod
    def get_exe_by_pid(pid):
        return LinuxLib._get_proctype_by_pid("exe", pid)

    @staticmethod
    def is_docker_proc(pid):
        target = "/proc/{!s}/cgroup".format(pid)
        if not os.path.isfile(target):
            return False

        tmp = []
        with open(target, "r") as f:
            tmp = [line for line in f]
        for l in tmp:
            if "docker" in l:
                return True

        return False

class MySQLLib(object):
    @staticmethod
    def list_mysql_pids():
        process_name = "mysqld"
        pids = set()
        for proc in psutil.process_iter():
            if process_name == proc.name():
                pids.add(proc.pid)
        return list(pids)

    @staticmethod
    def get_mysqld_version(mysqld_path):
        res = subprocess.check_output([mysqld_path, "--version"])
        return res.strip()

    @staticmethod
    def get_mysqld_confargs(ini_path):
        res = {}

        if not os.path.isfile(ini_path):
            return res

        cp = SafeConfigParser(allow_no_value = True)
        cp.read(ini_path)
        for i in cp.items("mysqld"):
            res[i[0]] = i[1]
        return res

    @staticmethod
    def get_mysqld_cmdargs(mysqld_pid):
        ignore_args = ("defaults-file",)
        res = {}
        for i in psutil.Process(mysqld_pid).cmdline()[1:]:
            line = i.lstrip("-")
            k = ""
            v = ""
            if "=" in line:
                k = line.split("=", 1)[0]
                v = line.split("=", 1)[1]
            else:
                k = line
            if k in ignore_args:
                continue
            res[k] = v
        return res

    @staticmethod
    def find_mysqld_confpath(mysqld_pid):
        cnf_lst = [
            "/etc/my.cnf", 
            "/etc/mysql/my.cnf", 
            "/usr/local/mysql/etc/my.cnf", 
            "~/.my.cnf", 
        ]
        res = ""
        for i in psutil.Process(mysqld_pid).cmdline()[1:]:
            if not i.startswith("--defaults-file"):
                continue
            res = i.split("=", 1)[1]

        if not res:
            for f in cnf_lst:
                if os.path.isfile(f):
                    res = f
                    break

        return res

    @staticmethod
    def find_mysqld_execpath(mysqld_pid):
        return LinuxLib.get_exe_by_pid(mysqld_pid)

def execute():
    res = {}
    pids = MySQLLib.list_mysql_pids()
    coll = {p: MySQLDiscovery(p) for p in pids}

    for p in coll:
        coll[p].scan_mysql_os()
        coll[p].scan_mysql_base()
        coll[p].scan_mysql_conf()

    for p in coll:
        res[p] = coll[p].get_res().get_res()

    print(json.dumps(res ,ensure_ascii=False))

if __name__ == "__main__":
    execute()