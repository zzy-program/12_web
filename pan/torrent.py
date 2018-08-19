# vim: se fileencoding=utf8
'''Usage:
  torrent [-v...] FILE...

Options:
  -v --verbose               Verbose mode.
'''

from __future__ import print_function
import bencode
import docopt
import glob
import logging
import os
import os.path
import sys

_patterns = None
def loadPatterns(ptnFileName):
  result = []
  if os.path.exists(ptnFileName):
    with open(ptnFileName, 'r') as f:
      for ptn in f:
        ptn = ptn.decode('utf8').strip()
        result.append(ptn)
  return result

def transformName(name):
  global _patterns
  if not _patterns:
    ptnFileName = os.path.splitext(__file__)[0] + '.ptn'
    _patterns = loadPatterns(ptnFileName)
  for ptn in _patterns:
    name = name.replace(ptn, '')
  return name

def doRename(opt, path, torrent):
  info = torrent['info']
  name = info.get('name.utf-8') or info.get('name')
  if name:
    name = name.decode('utf8')
    name = transformName(name)
    dir, src = os.path.split(path)
    dst = os.path.join(dir, name + os.path.splitext(src)[1])
    if path.decode('gb18030') != dst:
      if os.path.exists(dst):
        print('Rename %s failed, %s already exists.' % (src, dst), file=sys.stderr)
      else:
        if opt['--verbose'] > 0:
          print('Rename ', os.path.basename(path), ' to ', name, '.', sep='')
        os.rename(path, dst)
  else:
    print('Can not find name in %s.' % path)

def renameTorrent(opt):
  for pattern in opt['FILE']:
    ls = glob.glob(pattern)
    for name in ls:
      with open(name, 'rb') as f:
        torrent = bencode.bdecode(f.read())
      try:
        doRename(opt, name, torrent)
      except UnicodeDecodeError, e:
        print('Rename %s failed: %s' % (name, e), file=sys.stderr)
        logging.exception('Rename %s failed.', name)
  return 0

def main(opt):
  return renameTorrent(opt)

if '__main__' == __name__:
  try:
    opt = docopt.docopt(__doc__)
    verbose = opt['--verbose']
    if verbose > 3: verbose = 3
    logging.getLogger().setLevel(getattr(logging, ('ERROR', 'WARNING', 'INFO', 'DEBUG')[verbose]))
    logging.debug(opt)
    sys.exit(main(opt))
  except KeyboardInterrupt:
    print('Interrupted.')
