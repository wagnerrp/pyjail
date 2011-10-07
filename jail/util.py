#!/usr/bin/env python

import subprocess

debug = 1
null = open('/dev/null', 'w')

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

