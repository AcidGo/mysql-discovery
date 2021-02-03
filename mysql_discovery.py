# -*- conding: utf-8 -*-

# Author: AcidGo


import platform

class Result(object):
    def __init__(self):
        self._res = dict()

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

        if not self.pid and self.pid < 1:
            raise Exception("")

    def scan_mysql_os(self):
        typ = "OS"
        self.res.set_val(typ, "system", platform.system())
        self.res.set_val(typ, "platform", platform.platform())

    def scan_mysql_base(self):
        typ = "Base"

        conf_path = MySQLLib.find_mysqld_confpath(self.pid)
        exec_path = MySQLLib.find_mysqld_execpath(self.pid)
        mysqld_version = MySQLLib.get_mysqld_version(exec_path)

        self.res.set_val(typ, "conf_path", conf_path)
        self.res.set_val(typ, "exec_path", exec_path)
        self.res.set_val(typ, "mysqld_version", mysqld_version)

    def scan_mysql_conf(self):
        typ = "Conf"
        conf_path = MySQLLib.find_mysqld_confpath(self.pid)

        conf_dict = MySQLLib.get_mysqld_confargs(conf_path)
        cmdargs_dict = MySQLLib.get_mysqld_cmdargs(self.pid)
        conf_dict.update(cmdargs_dict)
        self.res.set_typ(conf_dict)

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

class MySQLLib(object):
    @staticmethod
    def list_mysql_pids():
        pids = set()
        for proc in psutil.process_iter():
            if process_name in proc.name():
                pids.add(proc.pid)
        return list(pids)

    @staticmethod
    def get_mysqld_version(mysqld_path):
        res = subprocess.check_output([mysqld_path, "--version"])
        return res.strip()

    @staticmethod
    def get_mysqld_confargs(ini_path):
        res = {}
        cp = ConfigParser.SafeConfigParser(allow_no_value = True)
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
        res = ""
        for i in psutil.Process(mysqld_pid).cmdline()[1:]:
            if not i.startswith("--defaults-file"):
                continue
            res = i.split("=", 1)[1]
        return res

    @staticmethod
    def find_mysqld_execpath(mysqld_pid):
        return LinuxLib.get_exe_by_pid(mysqld_pid)