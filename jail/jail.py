#!/usr/local/bin/python

import subprocess
import imp
import re
import os
import sys

debug = 1
null = open('/dev/null','w')

def Popen(*args, **kwargs):
    if debug:
        print 'Popen: ',args,kwargs
    if debug < 2:
        for pipe in ['stdout','stderr']:
            if pipe not in kwargs:
                kwargs[pipe] = null
    return subprocess.Popen(*args, **kwargs)

def call(*args, **kwargs):
    if debug:
        print 'call: ',args,kwargs
    if debug < 2:
        for pipe in ['stdout','stderr']:
            if pipe not in kwargs:
                kwargs[pipe] = null
    return subprocess.call(*args, **kwargs)

    @classmethod
    def apply(cls, mountpoint, ruleset):
        call(['/sbin/devfs','-m',mountpoint,'ruleset',str(ruleset)])
        call(['/sbin/devfs','-m',mountpoint,'rule','applyset'])

    @classmethod
    def mount(cls, mountpoint, ruleset):
        try:
            ruleset = int(ruleset)
            if ruleset not in cls._names.values():
                print 'Unknown devfs ruleset given, refusing to mount.'
                return
            mount('devfs', mountpoint, 'devfs')
            cls.apply(mountpoint, ruleset)
        except ValueError:
            cls.mount(mountpoint, cls._names[ruleset])
        
def mount(node, loc, type=None, opts={}):
    args = ['/sbin/mount']
    if type:
        args.append('-t')
        args.append(type)
    args.append(node)
    args.append(loc)
    if len(opts):
        args.append('-o')
        args.append(','.join(
                ['%s=%s' % i for i in opts.items()]))
    return call(args)

class Devfs( list ):
    _byid    = {}
    _byname  = {}

    _loaded  = []
    _files   = []

    @classmethod
    def fromdevfs(cls, name, id):
        id = int(id)
        if id in cls._byid:
            return cls._byid[id]

        lines = []
        devfs = Popen(['/sbin/devfs','rule','-s',str(id),'show'], stdout=-1)
        devfs.wait()
        for line in devfs.stdout:
            lines.append(line.strip())
        if len(lines):
            return cls.fromlines(name, id, lines)
        else:
            return None

    @classmethod
    def fromlines(cls, name, id, lines):
        id = int(id)
        if id in cls._byid:
            return cls._byid[id]

        ruleset = cls(name, id)
        for line in lines:
            if 'include' in line:
                s = line.split()
                tag = s[s.index('include')+1][1:]
                if tag in cls._byname:
                    ruleset += cls._byname[tag]
            else:
                ruleset.append(" ".join([part.strip("'") for part in line.split()]))
        ruleset.populated = True
        return ruleset

    def __repr__(self):
        return self.name

    def __init__(self, name, id):
        super(Devfs, self).__init__([])
        self.name = name
        self.id = int(id)
        self._lines = []
        self.populated = False

        self._byid[self.id] = self
        self._byname[self.name] = self

    def store(self, force=False):
        if (self.id in self._loaded):
            if not force:
                return

            call(['/sbin/devfs','rule','-s',str(self.id),'delset'])
            self._loaded.remove(self.id)

        for line in self:
            call(['/sbin/devfs','rule','-s',str(self.id)]+line.split())
        self._loaded.append(self.id)

    def apply(self, mountpoint):
        call(['/sbin/devfs','-m',mountpoint,'ruleset',str(self.id)])
        call(['/sbin/devfs','-m',mountpoint,'rule','applyset'])

    @classmethod
    def loadrunning(cls):
        cls._loaded = []
        devfs = Popen(['/sbin/devfs','rule','showsets'],stdout=-1)
        devfs.wait()

        for line in devfs.stdout:
            cls._loaded.append(int(line.strip()))

    @classmethod
    def _loadrules(cls, filename, force):
        if (filename in cls._files) and not force:
            return
        cls._files.append(filename)
        rulestart = re.compile('\[(?P<name>.*)=(?P<num>[0-9]+)\]')
        cname = None
        cnum = None
        lines = []

        for line in open(filename,'r'):
            line = line.strip()
            if len(line) == 0:
                continue
            if line.startswith('#'):
                continue
            match = rulestart.match(line)
            if match:
                if cname is not None:
                    cls.fromlines(cname,cnum,lines).store(force)

                cname, cnum = match.groups()
                lines = []
            else:
                lines.append(line)

        if cname is not None:
            cls.fromlines(cname,cnum,lines).store(force)

    @classmethod
    def loadrules(cls, filename=None, force=False):
        if len(cls._loaded) == 0:
            cls.loadrunning()
        if not filename:
            cls._loadrules('/etc/defaults/devfs.rules', force)
            cls._loadrules('/etc/devfs.rules', force)
        else:
            cls._loadrules(filename, force)

    @classmethod
    def mount(cls, mountpoint, ruleset):
        mount('devfs', mountpoint, 'devfs')
        if ruleset in cls._byid:
            cls._byid[ruleset].apply(mountpoint)
        elif ruleset in cls._byname:
            cls._byname[ruleset].apply(mountpoint)

class Jail( object ):
    enable      = True
    name        = None
    rootdir     = None
    hostname    = None
    exec_start  = '/bin/sh /etc/rc'
    exec_stop   = '/bin/sh /etc/rc.shutdown'
    exec_hold   = '/bin/sh'
    iface       = 're0'
    ip4         = ()
    ip6         = ()
    route       = None
    route6      = None
    vlan        = False
    devfs       = False
    devfs_rules = None
    procfs      = False
    mount       = False
    persist     = False
    hold_open   = '/bin/sh'

    running     = False
    jid         = None
    requires    = []
    provides    = ''

    _modules = {}

    @classmethod
    def loadlist(cls):
        path = '/usr/local/etc/jails'

        cls._modules.clear()
        for fname in os.listdir(path):
            if not fname.endswith('.py'):
                continue
            item = fname[:-3]
            try:
                cls._modules[item] = imp.load_source(item,
                                    os.path.join(path, fname)).task
                cls._modules[item].file = path+'/'+item+'.py'
            except:
                pass
        return cls._modules

    @classmethod
    def loadrunning(cls):
        if len(cls._modules) == 0:
            cls.loadlist()

        for module in cls._modules.values():
            module.running = False

        jls = Popen('/usr/sbin/jls',stdout=-1)
        jls.wait()

        for line in jls.stdout:
            try:
                id,ip,hn,rd = line.split()
                for module in cls._modules.values():
                    if not module.enable:
                        continue
                    if rd == module.rootdir:
                        module.running = True
                        module.jid = id
                        break
            except:
                pass

    @classmethod
    def sortlist(cls, command):
        if len(cls._modules) == 0:
            cls.loadlist()

        root = []
        for module in cls._modules.values():
            if len(module.requires) == 0:
                root.append(module)
                continue

            for req in list(module.requires):
                if req in cls._modules:
                    module.requires.remove(req)
                    module.requires.append(cls._modules[req])

        sorted = []
        loop = True
        while loop:
            loop = False
            for module in cls._modules.values():
                if (module in sorted) or not module.enable:
                    continue

                if len(module.requires) == 0:
                    sorted.append(module)
                    continue

                for req in module.requires:
                    if not req.enable:
                        module.enable = False
                        break
                    if req not in sorted:
                        loop = True
                        break
                else:
                    sorted.append(module)

        if command == 'stop':
            sorted = reversed(sorted)
        elif command == 'list':
            for module in cls._modules.values():
                if module not in sorted:
                    sorted.append(module)

        return sorted

    def __init__(self):
        if self.name is None:
            raise Exception('Jail must be named')
        if self.rootdir is None:
            raise Exception('Jail has no root directory')
        if self.hostname is None:
            self.hostname = self.name

        if self.devfs is True:
            self.devfs = 'devfsrules_jail'
        if self.mount:
            if self.mount is True:
                self.mount = self.name+'.fstab'
            if not self.mount.startswith('/'):
                self.mount = '/usr/local/etc/jails/'+self.mount

        self.rootdir = self.rootdir.rstrip('/')

    def runcommand(self, command):
        if command == 'start':
            self.start()
        elif command == 'stop':
            self.stop()
        elif command == 'restart':
            self.stop()
            self.start()
        elif command == 'poll':
            self.poll()
        elif command == 'applydevfs':
            self.applydevfs()
        elif command == 'list':
            print "{0:<25}{1:<10}{2}".format(self.name, str(self.enable), self.running)
        elif command == 'enable':
            self.enabletask()
        elif command == 'disable':
            self.disabletask()
        else:
            print 'invalid command'
            sys.exit(1)
    
    def _mount(self):
        if self.devfs:
            Devfs.loadrules()
            if self.devfs_rules:
                Devfs.loadrules(self.devfs_rules)
            Devfs.mount(self.rootdir+'/dev', self.devfs)

        if self.procfs:
            mount('proc', self.rootdir+'/proc', 'procfs')

        if self.mount:
            # check if exists
            call(['/sbin/mount','-a','-F',self.mount])

    def _umount(self):
        if self.mount:
            # check if exists
            call(['/sbin/umount','-a','-F',self.mount])
        if self.devfs:
            call(['/sbin/umount',self.rootdir+'/dev'])
        if self.procfs:
            call(['/sbin/umount',self.rootdir+'/proc'])

    def _ifprestart(self):
        if self.vlan:
            ifc = Popen(['/sbin/ifconfig','epair','create'], stdout=-1)
            ifc.wait()
            self._ifpair = ifc.stdout.readline().rstrip()[:-1]

            call(['/sbin/ifconfig','bridge0','addm',self._ifpair+'a'])
            call(['/sbin/ifconfig',self._ifpair+'a','up'])

        else:
            for ip in self.ip4:
                call(['/sbin/ifconfig',self.iface,'alias',ip,'netmask','255.255.255.255'])
            for ip in self.ip6:
                call(['/sbin/ifconfig',self.iface,'inet6',ip,'prefixlen','128'])

    def _ifpoststart(self):
        if not self.vlan:
            return
        self.loadrunning()
        id = self.jid
        pairb = self._ifpair+'b'
        call(['/sbin/ifconfig',pairb,'vnet',self.name])
        call(['/usr/sbin/jexec',id,'/sbin/ifconfig','lo0','127.0.0.1'])
        call(['/usr/sbin/jexec',id,'/sbin/ifconfig',pairb,self.ip4[0]])
        for ip in self.ip4[1:]:
            call(['/usr/sbin/jexec',id,'/sbin/ifconfig',pairb,'alias',ip])
        for ip in self.ip6:
            call(['/usr/sbin/jexec',id,'/sbin/ifconfig',pairb,'inet6',ip])
        if self.route:
            call(['/usr/sbin/jexec',id,'/sbin/route','add','default',self.route])
        if self.route6:
            call(['/usr/sbin/jexec',id,'/sbin/route','add','-inet6','default',self.route6])
        call(['/usr/sbin/jexec',id]+self.exec_start.split())

    def _ifprestop(self):
        if not self.vlan:
            return
        ifc = Popen(['/usr/sbin/jexec',self.jid,'/sbin/ifconfig'], stdout=-1)
        ifc.wait()

        for line in ifc.stdout:
            if line.startswith('\t'):
                continue
            int = line.split(':')[0]
            if int.startswith('epair') and int.endswith('b'):
                break
        self._ifpair = int[:-1]

    def _ifpoststop(self):
        if self.vlan:
            paira = self._ifpair+'a'
            call(['/sbin/ifconfig','bridge0','deletem',paira])
            call(['/sbin/ifconfig',paira,'destroy'])

        else:
            for ip in self.ip4:
                call(['/sbin/ifconfig',self.iface,'inet',ip,'delete'])
            for ip in self.ip6:
                call(['/sbin/ifconfig',self.iface,'inet6',ip,'delete'])

    def _buildcommand(self):
        cmd = ['/usr/sbin/jail','-l','-U','root','-c']
        cmd.append('path='+self.rootdir)
        cmd.append('name='+self.name)
        cmd.append('host.hostname='+self.hostname)
        if self.persist:
            cmd.append('persist')
        if self.vlan:
            cmd.append('vnet')
            cmd.append('command='+self.exec_hold)
        else:
            if len(self.ip4):
                cmd.append('ip4.addr='+','.join(self.ip4))
            if len(self.ip6):
                cmd.append('ip6.addr='+','.join(self.ip6))
            cmd += ('command='+self.exec_start).split()
        return cmd

    def start(self):
        if self.running:
            print self.name+' is already running'
            return False
        if not self.enable:
            return False
        print 'starting '+self.name
        self._mount()
        self._ifprestart()
        cmd = self._buildcommand()
        if self.vlan:
            jail = Popen(cmd, stdin=-1)
        else:
            jail = Popen(cmd)

        if jail.poll() > 0:
            print self.name+' failed'
            return

        self._ifpoststart()

        if self.vlan:
            if jail.poll() is None:
                jail.stdin.close()
        else:
            jail.wait()
        self.running = True

    def stop(self):
        if not self.running:
            print self.name+' is not running'
            return False
        if not self.enable:
            return False
        print 'stopping '+self.name
        self._ifprestop()
        call(['/usr/sbin/jexec',self.jid]+self.exec_stop.split())
        call(['/usr/sbin/jail','-r',self.jid])
        self._umount()
        self._ifpoststop()
        self.running = False
        return True

    def enabletask(self):
        f = open(self.file, 'r')
        buff = ''
        for line in f:
            if line.strip().startswith('enable'):
                buff += line.replace('False','True')
            else:
                buff += line
        f.close()

        f = open(self.file, 'w')
        f.write(buff)
        f.close()

    def disabletask(self):
        f = open(self.file, 'r')
        buff = ''
        for line in f:
            if line.strip().startswith('enable'):
                buff += line.replace('True', 'False')
            else:
                buff += line
        f.close()

        f = open(self.file, 'w')
        f.write(buff)
        f.close()

    def poll(self):
        if not self._isrunning():
            print self.name+' is not running'
        else:
            print self.name+' is running'

    def applydevfs(self):
        if not self.devfs:
            return
        if not self.running:
            print self.name+' is not running'
        Devfs.loadrules()
        if self.devfs_rules:
            Devfs.loadrules(self.devfs_rules)
        Devfs.apply(self.rootdir+'/dev', self.devfs)
