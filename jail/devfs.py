#!/usr/bin/env python

import re

from util import Popen, call, mount

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

    @classmethod
    def fromStore(cls, name):
        try:
            return cls._byname[name]
        except KeyError:
            return cls._byid[name]

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
