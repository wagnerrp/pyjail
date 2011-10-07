#!/usr/local/bin/python

import imp
import os
import sys

from devfs import Devfs
from util import Popen, call, mount

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
    ports       = False
    persist     = False
    hold_open   = '/bin/sh'
    raw_socket  = False
    alt_socket  = False

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
        if command not in ('forcestart', 'start', 'stop', 'restart', 'poll',
                           'list', 'enable', 'disable', 'applydevfs'):
            print 'invalid command'
            sys.exit(1)

        if command in ('enable', 'disable'):
            getattr(self, command+'jail')()
        else:
            getattr(self, command)()
    
    def _mount(self):
        if self.devfs:
            Devfs.loadrules()
            if self.devfs_rules:
                Devfs.loadrules(self.devfs_rules)
            Devfs.mount(self.rootdir+'/dev', self.devfs)

        if self.procfs:
            mount('proc', self.rootdir+'/proc', 'procfs')

        if self.ports:
            mount('/usr/ports', self.rootdir+'/usr/ports', 'nullfs')
            mount('/usr/ports/distfiles', self.rootdir+'/usr/ports/distfiles', 'nullfs')

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
        if self.ports:
            call(['/sbin/umount',self.rootdir+'/usr/ports/distfiles'])
            call(['/sbin/umount',self.rootdir+'/usr/ports'])

    def _ifprestart(self):
        if self.vlan:
            # search for existing usable vlan
            ifc = Popen(['/sbin/ifconfig'], stdout=-1)
            ifc.wait()
            pairs = {}
            for line in ifc.stdout:
                if not line.startswith('epair'):
                    continue
                pair = line.split(':')[0][:-1]
                if pair in pairs:
                    pairs[pair] += 1
                else:
                    pairs[pair] = 1
            for k,v in sorted(pairs.items()):
                if v == 2:
                    self._ifpair = k
                    break
            else:
                # create a new vlan
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
#            call(['/sbin/ifconfig',paira,'destroy'])

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
        if self.raw_socket:
            cmd.append("allow.raw_sockets")
        if self.alt_socket:
            cmd.append("allow.socket_af")
        return cmd

    def list(self):
        print "{0:<25}{1:<10}{2}".format(self.name, str(self.enable), self.running)

    def forcestart(self):
        self.start(True)

    def restart(self):
        self.stop()
        self.start()

    def start(self, force=False):
        if self.running:
            print self.name+' is already running'
            return False
        if not (self.enable or force):
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
#        if not self.enable:
#            return False
        print 'stopping '+self.name
        self._ifprestop()
        call(['/usr/sbin/jexec',self.jid]+self.exec_stop.split())
        call(['/usr/sbin/jail','-r',self.jid])
        self._umount()
        self._ifpoststop()
        self.running = False
        return True

    def enablejail(self):
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

    def disablejail(self):
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
        Devfs.fromStore(self.devfs).apply(self.rootdir+'/dev')
