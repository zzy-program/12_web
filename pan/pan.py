# vim: se fileencoding=utf8
'''Usage:
  pan shell [-v...]
  pan list [-v...] [-ic COOKIE -d DIR]
  pan download [-v...] [-o OUTPUT] URL
  pan delete [-v...] PATH...
  pan rapid-upload [-v... -d DIR] FILE_OR_URL...

Options:
  -i --interactive           Use interactive mode.
  -c COOKIE --cookie=COOKIE  Set request cookies.
  -d DIR --dir=DIR           Set the remote directory [default: /download].
  -o OUTPUT --output=OUTPUT  Set output file name.
  -v --verbose               Verbose mode.
'''

# from gevent.monkey import patch_all

import datetime
import fnmatch
import hashlib
import json
import logging
import os
import os.path
try:
	import pynotify
except ImportError:
  pynotify = None
import requests
import sys
import subprocess
import time
import urllib
import urlparse
import zlib

import docopt

from torrent import transformName

API_PREFIX = 'http://pan.baidu.com/api/'
#API_PREFIX = 'http://localhost/api/'
API_MANAGE = API_PREFIX + 'filemanager?web=1'
API_RAPID_UPLOAD = API_PREFIX + 'rapidupload?clienttype=6&version=2.0.0.4'
API_GET_DL_LINK = API_PREFIX + 'download?channel=chunlei&clienttype=0&web=1'

_COOKIE = 'H5sb0pkWlNIZnRjWWRBdUZLbkpoRnpRWHVxeERmNDJhLXh1bmZQLXRoUE4zLXBVQVFBQUFBJCQAAAAAAAAAAAEAAACsiEUCenp5anNqY29tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM1Sw1TNUsNUS'

class Mime(object):
  def __init__(self, name=None, value=None):
    self.name = name
    self.value = value
    self._parse()

  def _parse(self):
    self.params = {}
    if self.value is not None:
      arr = self.value.split(';')
      self.realValue = arr[0].strip()
      for i in arr[1:]:
        idx = i.index('=')
        k = i[:idx].strip()
        v = i[idx+1:].strip()
        self.params[k] = v
    else:
      self.realValue = self.value

def getDlSign(context):
  args = [
      'node',
      os.path.join(os.path.dirname(__file__), 'pan_sign.js'),
      'BDUSS=' + context['cookie'],
  ]
  try:
    sign = subprocess.check_output(args).strip()
    logging.debug('Download sign: %s', sign)
    return sign
  except subprocess.CalledProcessError, e:
    print 'Get download sign error:', e.returncode
    logging.debug(e.output)
    return None

def getDlink(context, item):
  '''
POST /api/download?channel=chunlei&clienttype=0&web=1&bdstoken=358eef769288e1721ad863e9167985af HTTP/1.1
Host: pan.baidu.com
Connection: keep-alive
Content-Length: 129
Accept: */*
Origin: http://pan.baidu.com
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.132 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: http://pan.baidu.com/disk/home
Cookie: BDUSS=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

sign=8UhAPMZWSGmiAjRNBgbC9AYu%2FmPxbmnYKEDm0JcJt35hRcWgK3jV0g%3D%3D&timestamp=1399692064&fidlist=%5B703532892607068%5D&type=dlink

{"errno":0,"request_id":566610287,"dlink":[{"fs_id":"703532892607068","dlink":"http:\/\/d.pcs.baidu.com\/file\/ae1e7f5426a8d7073e2def651fafdf73?fid=2148494985-250528-703532892607068&time=1399692558&rt=pr&sign=FDTAER-DCb740ccc5511e5e8fedcff06b081203-4GJ4%2BacDa5cEMHHEcH3up9KIbkQ%3D&expires=8h&prisign=OPlXeyLLE60gMv0\/AZBsU5SN5rJwOqzRzN209TMfvpUT235wEv1x9ebqO6VVFUbJ1Ms9seOiqT9\/QffwI8K2Baw0mmLABRQNl51b\/oS8+InqoadADmwcypNo\/dTFHAxE\/EdcOMU\/LDe5Yk3oaKaHUoLgzh+qonpalNnA+pfMKYDycgI5A4W\/Ju5XK\/lbx40bmYmZ6iiLeaYmSHmR3\/fsWXmhqryF3Ugcv0g6P0mYT2\/phEB25+g0Yg==&r=363097184"}]}

errno == 112: expired.
  '''

  sign = getDlSign(context)
  if not sign: return None
  data = "%s&type=dlink&fidlist=%%5B%s%%5D" % (sign, item['fs_id'])
  result = api(context, API_GET_DL_LINK, data)
  errno = result['errno']
  if errno == 0:
    return result['dlink'][0]['dlink']
  else:
    return None

if pynotify:
  def notify(msg, title='Pan', icon='info'):
    if not pynotify.is_initted(): pynotify.init('Pan')
    notification = pynotify.Notification(title, msg, icon)
    notification.show()
else:
  def notify(*args, **kw): pass

def download(opt):
  output = opt.get('--output', 'bs.tmp')
  cookie = opt['--cookie'] or _COOKIE
  url = opt['URL']
  if not url:
    print 'Download url is not available.'
    return 5
  if os.path.exists(output):
    logging.warning('%s already exists.', output)
    return 4
  tmpOutput, cl = output + '.pan', -1
  with open(tmpOutput, 'a+b') as of:
    of.seek(0, os.SEEK_END)
    pos = of.tell()
    logging.debug('file pos: %d', pos)

    headers = {} if pos == 0 else {'Range': 'bytes=%d-' % pos}
    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36'
    headers['Referer'] = 'http://pan.baidu.com/disk/home'
    logging.debug('Request headers: %s', headers)
    try:
      resp = requests.get(
        url,
        headers=headers,
        stream=True,
        cookies={'BDUSS': cookie},
      )
      sc = resp.status_code
      logging.debug('Status code: %d', sc)
      logging.debug('Response headers: %s', resp.headers)
      if (pos == 0 and sc == 200) or (pos != 0 and sc == 206):
        while True:
          data = resp.raw.read(1024 * 256)
          if len(data) == 0: break
          sys.stdout.write('.')
          sys.stdout.flush()
          of.write(data)
        sys.stdout.write('\n')
        if sc == 200:
          cl = int(resp.headers.get('content-length', 0))
        else:
          rh = resp.headers.get('content-range', '/-1')
          cl = int(rh[rh.index('/')+1:])
    except IOError, e:
      logging.exception('Network error.')
    except KeyboardInterrupt:
      print 'Interrupted, download cancelled.'
      return 0

  fs = os.stat(tmpOutput).st_size
  if cl != -1:
    if fs == cl:
      md5 = resp.headers.get('content-md5')
      if checkMd5(tmpOutput, md5):
        os.rename(tmpOutput, output)
        print '%s download complete.' % output
        notify('%s download complete' % output)
        return 0
      else:
        logging.error('%s md5 error, expect %s.', output, md5)
        os.rename(tmpOutput, output + '.error')
        return 5
    elif fs > cl:
      logging.error('File %s too large: %d > %d.', tmpOutput, fs, cl)
    else:
      print 'Downloading file %s interrupted.' % output

def checkMd5(fileName, md5):
  if md5 is None:
    logging.warning('Md5 is not available for %s', fileName)
    return True
  with open(fileName, 'rb') as input:
    m = hashlib.md5()
    while True:
      data = input.read(4096)
      if len(data) == 0: break
      m.update(data)
    logging.debug('%s md5: %s', fileName, m.hexdigest())
    return m.hexdigest().lower() == md5.lower()

def input(opt):
  ps1 = 'pan> '
  while True:
    cmd = raw_input(ps1).split()
    if not cmd: continue
    return cmd

def shortcut(context, cmd):
  first = cmd[0]
  if not first.isdigit(): return
  ls = context.get('list')
  if ls is None: return
  first = int(first)
  if first >=0 and first < len(ls):
    item = ls[first]
    if item['isdir'] == 0:
      cmd.insert(0, 'd')
    else:
      cmd.insert(0, 'l')

def interactive(opt):
  if sys.platform != 'win32':
    try:
      import readline
    except ImportError as e:
      logging.info('Module "readline" is not available.')

  result = 0
  context = {
      'opt': opt,
      'dir': opt['--dir'],
      'cookie': opt['--cookie'] or _COOKIE,
  }
  while True:
    cmds = input(opt)
    shortcut(context, cmds)
    cmd = cmds.pop(0)
    func = available.get(cmd)
    if func is None:
      print 'Unknown command: %s' % cmd
    else:
      context['params'] = cmds
      result = func(context)
    context.pop('params', None)
  return result

def list(opt):
  cookie = opt['--cookie'] or _COOKIE
  dir = opt['--dir']

  oldDir = None
  while True:
    if oldDir != dir:
      errno, ls = doList(dir, cookie)
    if errno != 0 or not opt['--interactive']: break
    oldDir = dir
    choice = raw_input('Choice: ').strip()
    if choice == 'r':
      oldDir = None
    elif choice[0] == 'd':
      deleteCmd()
    else:
      choice = int(choice)
      if choice >= 0 and choice < len(ls):
        item = ls[choice]
        if item['isdir'] != 0:
          dir = item['path']
        else:
          if 'dlink' in item:
            dlink = item['dlink'] + '&cflg=65535%3A1'
          else:
            dlink = getDlink({'cookie': cookie}, item)
          dlOpt = {
              '--output': transformName(item['server_filename']),
              'URL': dlink,
              '--cookie': cookie,
          }
          download(dlOpt)
      elif choice == -1:
        idx = dir.rfind('/')
        if idx >= 0:
          dir = dir[0:idx] or '/'
      else:
        print 'Bad choice.'

def doList(dir, cookie):
  '''
  GET /api/list?web=1&dir=%2Fdownload%2FSnowpiercer.2013.720p.BluRay.x264.DTS-WiKi&order=time HTTP/1.1
  Host: pan.baidu.com
  Cookie: BDUSS=xxxxxxxxxxxxx
  '''
  params = {
      'web': 1,
      'order': 'time',
      'dir': dir,
  }
  resp = requests.get('http://pan.baidu.com/api/list', params=params, cookies={'BDUSS': cookie})
  json = resp.json()
  errno, ls = json['errno'], json['list']
  if errno == 1:
    print 'Invalid cookie.'
  elif errno == 0:
    for i, item in enumerate(ls):
      name = transformName(item['server_filename'])
      print '%2d %s %s' % (i, ' d'[item['isdir']], name)
    print 'Total %d files in %s' % (len(ls), dir)
  else:
    print 'Unknown error: %d' % errno
  return errno, ls

def delete(opt):
  '''
Request:
POST /api/filemanager?web=1&opera=delete HTTP/1.1
Host: pan.baidu.com
Content-Length: 93
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: BDUSS=xxxxxxxxxxxxxxxxxxxx

filelist=%5B%22%2Fdownload%2Ftorrent%2Fb65e4bf72b46730a02eaa4f59ee8af5b030b8f3f.torrent%22%5D

Response:
{"errno":0,"info":[{"errno":0,"path":"\/download\/torrent\/b65e4bf72b46730a02eaa4f59ee8af5b030b8f3f.torrent"}],"request_id":1306184071}
  '''
  path = opt['PATH']
  cookie = opt['--cookie'] or _COOKIE
  params = {
      'opera': 'delete',
  }
  data = {'filelist': json.dumps(path)}
  resp = requests.post(API_MANAGE, cookies={'BDUSS': cookie}, params=params, data=data)
  result = resp.json()
  errno = result['errno']
  logging.info('Delete errno: %d', errno)
  if errno != 0:
    for info in result['info']:
      logging.debug('Delete %(path)s: %(errno)d', info)
  return 0 if errno == 0 else 2

def api(context, url, data=None, params=None):
  cookie = context['cookie']
  if params:
    logging.debug('Parameters: %s', params)
  if data:
    logging.debug('Request data: %s', data)
  headers = {
      'Referer': 'http://pan.baidu.com/disk/home',
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.132 Safari/537.36',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
  }
  resp = requests.post(
      url,
      cookies={'BDUSS': cookie},
      params=params,
      data=data,
      headers=headers,
  )
  logging.debug('Response: %s', resp.text)
  return resp.json()

def move(context, op):
  '''
  Content-Type:application/x-www-form-urlencoded; charset=UTF-8

  filelist:[{"path":"/download/飞鸟娱乐(bbs.hdbird.com).大峡谷.720p.中英字幕","dest":"/download/done","newname":"飞鸟娱乐(bbs.hdbird.com).大峡谷.720p.中英字幕"}]

  {"errno":0,"info":[{"errno":0,"path":"\/download\/\u98de\u9e1f\u5a31\u4e50(bbs.hdbird.com).\u5927\u5ce1\u8c37.720p.\u4e2d\u82f1\u5b57\u5e55"}],"request_id":3068196243}
  '''
  data = {'filelist': json.dumps(op)}
  params = {'opera': 'move'}
  resp = api(context, API_MANAGE, data, params)
  if resp['errno'] == 0: return 0
  logging.info('Move file error: %d', resp['errno'])
  for info in resp['info']:
    if info['errno'] == -8:
      print info['path'], 'already exists.'
    else:
      print '%(path)s error: %(errno)d' % info
  return 2

def listDir(context):
  params = context.get('params')
  if params is not None and len(params) > 0:
    if len(params) != 1:
      print 'Only accept 1 parameter.'
      return 2
    param = params[0]
    if param.isdigit() and context['list'] is not None:
      i, ls = int(param), context['list']
      if i >=0 and i < len(ls):
        context['dir'] = ls[i]['path']
      else:
        print 'Out of index: %d' % i
        return 2
    elif param.startswith('/'):
      context['dir'] = param
    else:
      print 'Ivalid parameter: %s' % param
  dir = context['dir']
  cookie = context['cookie']

  errno, ls = doList(dir, cookie)
  if errno == 0:
    context['list'] = ls
    return 0
  else:
    return 3

def listParent(context):
  dir = os.path.dirname(context['dir'])
  context['params'] = [dir]
  return listDir(context)

def getItem(context, idx=0):
  ls = context.get('list')
  if ls is None or len(ls) == 0:
    print 'List is emtpy.'
    return None
  params = context.get('params')
  if params is None or idx >= len(params) or not params[idx].isdigit():
    print 'Invalid parameters.'
    return None
  param = int(params[idx])
  if param >= 0 and param < len(ls):
    return ls[param]
  print 'Out of index: %d' % param
  return None

def humanSize(item):
  if item['isdir']: return '   -'
  size = item['size']
  idx = 0
  while size >= 1024:
    size /= 1024.
    idx += 1
  return '%.1f%s' % (size, 'BKMGT'[idx])

def downloadFile(context):
  ls, params = context['list'], context['params']
  if ls is None:
    print 'List is empty.'
    return 3
  if len(params) != 1 and not params[0].isdigit():
    print 'Invalid parameters.'
    return 3
  param = int(params[0])
  if param >=0 and param < len(ls):
    item = ls[param]
    if 'dlink' in item:
      dlink = item['dlink'] + '&cflg=65535%3A1'
    else:
      dlink = getDlink(context, item)
    dlOpt = {
        '--output': transformName(item['server_filename']),
        'URL': dlink,
        '--cookie': context['cookie'],
    }
    return download(dlOpt)
  print 'Out of index: %d' % param
  return 3

def downloadFileEx(context):
  count = 1000
  while count > 0:
    last = time.time()
    if 0 == downloadFile(context): break
    now = time.time()
    tmp = 10 + last - now
    if tmp > 0:
      time.sleep(tmp)
    last = now
    count -= 1

def deleteFile(context):
  params = context['params']
  if len(params) == 0:
    print 'Parameters required.'
    return 3
  items = [getItem(context, i) for i in xrange(len(params))]
  if not all(items):
    print 'Invalid parameters.'
    return 3
  path = [item['path'] for item in items]
  delete({'PATH': path, '--cookie': context['cookie']})

def showList(context):
  ls = context.get('list')
  if ls:
    for i, item in enumerate(ls):
      name = transformName(item['server_filename'])
      print '%2d %s %s' % (i, ' d'[item['isdir']], name)
    print 'Total %d files in %s' % (len(ls), context.get('dir', '*Unknown*'))
  else:
    print 'List is empty.'

def moveFile(context):
  params = context.get('params')
  if not params or len(params) < 2:
    print 'Invalid parameter.'
    return 3
  sources = []
  for param in params[:-1]:
    sources.extend(resolveFile(context, param) or ())
  if len(sources) == 0:
    print 'Source file error.'
    return 2

  dst = params[-1]
  if dst.isdigit():
    dst = getItem(context, 1)
    if dst is None or not dst['isdir']:
      print 'Destination error.'
      return 3
    dst = dst['path']

  ops = [
      {
        'path': i['path'],
        'dest': os.path.normpath(os.path.join(os.path.dirname(i['path']), dst)).replace('\\', '/'),
        'newname': i['server_filename'],
      }
      for i in sources
  ]
  return move(context, ops)

def resolveFile(context, pattern):
  ls = context['list']
  if pattern.isdigit():
    idx = int(pattern)
    if ls is None or idx < 0 or idx >= len(ls):
      return None
    return ls[idx:idx+1]
  result = []
  if '?' in pattern or '*' in pattern:
    for file in ls:
      if fnmatch.fnmatch(file['server_filename'], pattern):
        result.append(file)
  else:
    result.append(pattern)
  return result

def showDetail(context):
  item = getItem(context)
  if item is None:
    return 3
  logging.debug('Detail: %s', item)
  print 'name: %s' % item['server_filename']
  print 'data: %s' % datetime.datetime.fromtimestamp(item['local_mtime']).strftime('%Y-%m-%d %X')
  print 'size: %s (%d)' % (humanSize(item), item['size'])
  print 'md5:  %s' % item['md5']

def verbose(context):
  params = context.get('params')
  opt = context['opt']

  if len(params) == 0:
    print 'Verbosity:', ('ERROR', 'WARNING', 'INFO', 'DEBUG')[opt['--verbose']]
    return 0
  param = params[0]
  try:
    param = int(param)
  except (ValueError, TypeError):
    param = {
        'error':   0,
        'warning': 1,
        'info':    2,
        'debug':   3,
    }.get(param.lower())
    if param is None:
      print 'Parameter must be integer'
      return 2
  opt['--verbose'] = param
  setLogLevel(opt)


def showHelp(context):
  print '''  p    Show current lists.
  l    List remote directory.
  d    Download a file.
  dd   Download a file and retry if failed.
  m    Move a file to another directory.
       Wildcards '?' and '*' can be used.
  f    Show file's detail information.
  del  Delete a file.
  ..   List parent directory.
  v    Show/adjust verbosity.
  q    Quit.
  h    Show this help message.
  '''

available = {
    'p': showList,
    'l': listDir,
    'd': downloadFile,
    'dd': downloadFileEx,
    'm': moveFile,
    'f': showDetail,
    'h': showHelp,
    'del': deleteFile,
    'v': verbose,
    'q': lambda c: sys.exit(0),
    '..': listParent,
}

_SLICE_SIZE = 256 * 1024
class ApiException(Exception): pass

def genRapidUploadUrlFromFile(path):
  with open(path, 'rb') as f:
    md5 = hashlib.md5()
    slice = f.read(_SLICE_SIZE)
    if len(slice) != _SLICE_SIZE:
      raise ApiException(1, 'Rapid upload file size must larger than 256 * 1024 bytes.')

    contentLength = _SLICE_SIZE
    md5.update(slice)
    sliceMd5 = md5.hexdigest()
    contentCrc32 = zlib.crc32(slice) & 0xffffffff

    while True:
      slice = f.read(_SLICE_SIZE)
      if len(slice) == 0: break
      contentLength += len(slice)
      md5.update(slice)
      contentCrc32 = zlib.crc32(slice, contentCrc32) & 0xffffffff
    contentMd5 = md5.hexdigest()

    # Currently parameter "content-crc32" does not required.
    return 'http://pan/%s?content-length=%d&slice-md5=%s&content-md5=%s&content-crc32=%d' % (
        os.path.basename(path),
        contentLength,
        sliceMd5,
        contentMd5,
        contentCrc32,
    )

def rapidUploadUrl(opt, url):
  '''
POST /api/rapidupload?clienttype=6&version=2.0.0.4 HTTP/1.1
Connection: keep-alive
X-Requested-With: XMLHttpRequest
User-Agent: netdisk;2.0.0.4;PC;PC-Windows;5.1.2600;uploadplugin
Content-Type: application/x-www-form-urlencoded
Accept: */*
Accept-Language: zh-CN,zh;q=0.8
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Cookie: BDUSS=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Host: pan.baidu.com
Content-Length: 205
Cache-Control: no-cache

path=%2F%2FAs.The.Liht.Goes.Out.2014.1080p.WEB-DL.x264.AC3-SmY.mkv&content-md5=9e5456912e03b41737c5dd20144b4664&slice-md5=ad43250e103e77bb97ca261a067c56c0&content-crc32=1555154583&content-length=2317293358

HTTP/1.1 200 OK
Set-Cookie: BAIDUID=xxxxxxxxxxxxxxx; max-age=31536000; expires=Sat, 09-May-15 05:38:27 GMT; domain=.baidu.com; path=/; version=1
P3P: CP=" OTI DSP COR IVA OUR IND COM "
Date: Fri, 09 May 2014 05:38:28 GMT
Content-Type: application/json; charset=UTF-8
Cache-Control: no-cache
Server: lighttpd
X-Powered-By: PHP/5.4.24
Pragma: no-cache
yld: 3085352427591867484
yme: ZIGW+CYrXUsMbjcZTmvho21Xvv0=
Content-Length: 279

{"errno":0,"info":{"size":2317293358,"category":1,"isdir":0,"request_id":3843395996,"path":"\/As.The.Liht.Goes.Out.2014.1080p.WEB-DL.x264.AC3-SmY.mkv","fs_id":786278681156121,"md5":"9e5456912e03b41737c5dd20144b4664","ctime":1399613907,"mtime":1399613907},"request_id":2201709789}
  '''
  cookie = opt['--cookie'] or _COOKIE
  pr = urlparse.urlsplit(url)
  path = opt['--dir'] + pr.path
  data = 'path=%s&%s' % (urllib.quote_plus(path, safe=''), pr.query)
  logging.debug('Data: %s', data)

  resp = requests.post(API_RAPID_UPLOAD, cookies={'BDUSS': cookie}, data=data)
  result = resp.json()

  logging.debug(result)
  errno = result['errno']
  if errno != 0:
    if errno == -8:
      print 'File "%s" already exists.' % path
    elif errno == 404:
      print 'Can not find such file on server:', pr.path[1:]
    else:
      print 'Rapid upload error:', errno 
  return errno

def rapidUpload(opt):
  for url in opt['FILE_OR_URL']:
    url = url.strip()
    if not url.startswith('http://pan/'):
      try:
        url = genRapidUploadUrlFromFile(path=url)
      except (IOError, ApiException), e:
        print 'File %s error: %s' % (url, e)
        continue
    errno = rapidUploadUrl(opt, url)

def main(opt):
  if opt['shell']:
    return interactive(opt)
  if opt['list']:
    return list(opt)
  if opt['delete']:
    return delete(opt)
  if opt['rapid-upload']:
    return rapidUpload(opt)
  return 1

def setLogLevel(opt):
    verbose = opt['--verbose']
    if verbose > 3: verbose = 3
    if verbose < 0: verbose = 0
    opt['--verbose'] = verbose
    logging.getLogger().setLevel(getattr(logging, ('ERROR', 'WARNING', 'INFO', 'DEBUG')[verbose]))

if '__main__' == __name__:
  try:
    opt = docopt.docopt(__doc__)
    setLogLevel(opt)
    verbose = opt['--verbose']
    if verbose > 3: verbose = 3
    logging.getLogger().setLevel(getattr(logging, ('ERROR', 'WARNING', 'INFO', 'DEBUG')[verbose]))
    logging.debug(opt)
    sys.exit(main(opt))
  except KeyboardInterrupt:
    print 'Interrupted.'
