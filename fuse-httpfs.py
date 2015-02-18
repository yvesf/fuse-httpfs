#!/usr/bin/env python3
import os
import time
import logging
import logging.config
import sys
from urllib.parse import quote, unquote
from email.utils import parsedate
from html.parser import HTMLParser
from stat import S_IFDIR, S_IFREG
from errno import EIO, ENOENT, EBADF, EHOSTUNREACH

import fuse
import requests

FORMAT = "%(threadName)s %(asctime)-15s %(levelname)s:%(name)s %(message)s"
logging.basicConfig(level=logging.INFO, format=FORMAT)


class Config(object):
    mountpoint = None
    timeout = (5, 25)  # connect_timeout, read_timeout


def readNetrcMachines():
    machines = []
    fh = open(os.path.expanduser("~/.netrc"), "r")
    for line in fh.readlines():
        a, b, *c = line.split(" ")
        if a == "machine" and c == []:
            machines.append(b.strip())
    logging.info("Found netrc machines: {}".format(machines))
    return machines


class Path:
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name
        self.initialized = False

    def buildUrl(self):
        return self.parent.buildUrl() + "/" + quote(self.name)

    def getSession(self):
        return self.parent.getSession()

    def getAttr(self):
        raise fuse.FuseOSError(ENOENT)

    @classmethod
    def fromPath(clazz, parent, pathElement):
        p = clazz(parent, unquote(pathElement))
        logging.info("created {} '{}' referencing {}".format(
            clazz.__name__, p.name, p.buildUrl()))
        return p


class File(Path):
    def __init__(self, parent, name):
        super().__init__(parent, name)
        self.lastModified = None
        self.size = None

    def init(self):
        url = self.buildUrl()
        logging.info("File url={} name={}".format(url, self.name))
        r = self.getSession().head(url, timeout=Config.timeout)
        r.close()
        if r.status_code != 200:
            error = "Status code != 200 for {}: {}".format(url, r.status_code)
            raise Exception(error)
        self.size = int(r.headers['content-length'])
        self.lastModified = time.mktime(parsedate(r.headers['last-modified']))

        self.initialized = True

    def get(self, size, offset):
        if not self.initialized:
            self.init()
        url = self.buildUrl()
        bytesRange = '{}-{}'.format(offset, min(self.size, offset+size-1))
        headers = {'range': 'bytes=' + bytesRange}
        logging.info("File.get url={} range={}".format(url, bytesRange))
        r = self.getSession().get(url, headers=headers, timeout=Config.timeout)
        r.close()
        if r.status_code == 200 or r.status_code == 206:
            d = r.content
            logging.info("Received {} bytes".format(len(d)))
            if len(d) > size:
                errormsg = "size {} > than expected {}".format(len(d), size)
                logging.error(errormsg)
                raise fuse.FuseOSError(EIO)
            return d
        else:
            raise fuse.FuseOSError(EIO)

    def getAttr(self):
        if not self.initialized:
            self.init()
        t = self.lastModified
        return dict(st_mode=(S_IFREG | 0o444), st_nlink=1, st_size=self.size,
                    st_ctime=t, st_mtime=t, st_atime=t)


class Directory(Path):
    def __init__(self, parent, name):
        super().__init__(parent, name)
        self.entries = {}

    def init(self):
        url = self.buildUrl() + "/"
        logging.info("Directory url={} name={}".format(url, self.name))
        r = self.getSession().get(url, stream=True, timeout=Config.timeout)
        if r.status_code != 200:
            raise Exception("Status code not 200 for {}: {}".format(
                url, r.status_code))

        if "text/html" not in r.headers['content-type']:
            raise Exception("Is not text/html: {}".format(url))

        parser = RelativeLinkCollector(self)
        for line in r.iter_content(decode_unicode=True):
            parser.feed(line)
            self.entries.update(parser.entries)
            parser.entries.clear()
        parser.close()
        self.entries.update(parser.entries)
        r.close()

        logging.info("Diretory loaded {}".format(url))
        self.initialized = True

    def getAttr(self):
        t = time.time()
        nentries = 2 + len(self.entries)
        if self.initialized:
            nentries += len(self.entries)
        return dict(st_mode=(S_IFDIR | 0o555), st_nlink=nentries,
                    st_ctime=t, st_mtime=t, st_atime=t)


class Server(Directory):
    def __init__(self, parent, name):
        super().__init__(parent, name)
        self.session = requests.Session()

    def getSession(self):
        return self.session


class Schema(Directory):
    def __init__(self, parent, name):
        super().__init__(parent, name)
        self.initialized = True

    def buildUrl(self):
        return self.name + ":/"


class Root(Directory):
    def __init__(self):
        super().__init__(None, "")
        self.initialized = True

    def buildUrl(self):
        return ""


class RelativeLinkCollector(HTMLParser):
    def __init__(self, parent):
        super().__init__(self)
        self.parent = parent
        self.entries = {}

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attrs = dict(attrs)
            if "href" in attrs:
                href = attrs["href"]
                if "/" in href[:-1] or href[0] == ".":
                    return

                if href[-1:] == "/":
                    d = Directory.fromPath(self.parent, href[:-1])
                    self.entries[unquote(href[:-1])] = d
                else:
                    f = File.fromPath(self.parent, href)
                    self.entries[unquote(href)] = f


class HttpFs(fuse.LoggingMixIn, fuse.Operations):
    """A read only http/https/ftp filesystem using python-requests."""
    def __init__(self):
        self.root = Root()

        https = Schema(self.root, 'https')
        https.entries = dict(self._getDefaultEntries(https))
        http = Schema(self.root, 'http')
        http.entries = dict(self._getDefaultEntries(http))

        self.root.entries = {'http': http, 'https': https}

    def _getDefaultEntries(self, parent):
        for machine in readNetrcMachines():
            yield (machine, Server(parent, machine))

    def getattr(self, path, fh=None):
        logging.info("getattr path={}".format(path))
        try:
            entry = self._getPath(path)
            if entry:
                return entry.getAttr()
        except Exception as e:
            logging.error("Error", e)
            raise fuse.FuseOSError(EHOSTUNREACH)
        raise fuse.FuseOSError(ENOENT)

    def _getPath(self, path):
        """ map path to self.root tree
        a path is build like /<schema>/<server hostname>/<http-path>"""
        logging.debug("getPath path={}".format(path))
        if path == "/":
            return self.root

        schema, *p = path[1:].split("/")
        if schema not in self.root.entries:
            return None
        prevEntry = self.root.entries[schema]
        if p == []:
            return prevEntry

        server, *p = p
        if server not in prevEntry.entries:
            # create server if not exists
            prevEntry.entries[server] = Server.fromPath(prevEntry, server)
        prevEntry = prevEntry.entries[server]
        if p == []:
            return prevEntry

        *pathElements, lastElement = p
        for pathElement in pathElements:
            if pathElement not in prevEntry.entries:
                d = Directory.fromPath(prevEntry, pathElement)
                prevEntry.entries[pathElement] = d
            prevEntry = prevEntry.entries[pathElement]

        if lastElement not in prevEntry.entries:
            if not prevEntry.initialized:
                prevEntry.init()
            if lastElement not in prevEntry.entries:
                # the server don't return it, then just create it
                # assuming its an directory, if a HEAD is successful
                d = Directory.fromPath(prevEntry, lastElement)
                r = d.getSession().head(d.buildUrl() + "/",
                                        timeout=Config.timeout)
                if r.status_code == 200:
                    logging.info("Create directory for path which was not " +
                                 "discovered by Index of: {}".format(path))
                    prevEntry.entries[lastElement] = d
                else:
                    logging.info("Path not found: {}".format(path))
                    return None
        return prevEntry.entries[lastElement]

    def readdir(self, path, fh):
        entry = self._getPath(path)
        if not entry:
            raise fuse.FuseOSError(EBADF)
        if not entry.initialized:
            entry.init()
        return [(".", entry.getAttr(), 0),
                ("..", (entry.parent and entry.parent.getAttr() or None), 0)] \
            + [(it.name, it.getAttr(), 0) for it in entry.entries.values()]

    def read(self, path, size, offset, fh):
        entry = self._getPath(path)
        if isinstance(entry, File):
            return entry.get(size, offset)
        else:
            raise fuse.FuseOSError(EIO)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("mountpoint", nargs=1, help="Target directory")
    p.add_argument("--max_background", type=int, default=15,
                   help="Maximum number of background threads")
    p.add_argument("--no_foreground", action="store_true", default=False,
                   help="Fork into background as a daemon")
    p.add_argument("--debug", action="store_true", help="Stay foreground")
    p.add_argument("--nothreads", action="store_true", help="Stay foreground")
    p.add_argument("--connect_timeout", type=int,
                   default=Config.timeout[0], help="HTTP connect timeout")
    p.add_argument("--read_timeout", type=int,
                   default=Config.timeout[1], help="HTTP read timeout")

    args = vars(p.parse_args(sys.argv[1:]))
    kwargs = {}
    Config.timeout = (args.pop("connect_timeout"), args.pop("read_timeout"))
    Config.mountpoint = args.pop("mountpoint")[0]
    if not args.pop("no_foreground"):
        kwargs["foreground"] = True
    if args.pop("debug"):
        kwargs["debug"] = True
    kwargs.update(args)

    fuse = fuse.FUSE(HttpFs(), Config.mountpoint, **kwargs)
