"""
    Author: Reginald Holmes
    Date: May 2018
"""
import os
import sys
import re
import getopt
import pefile
from PIL import Image, ImageDraw, ImageFont
DEBUG = False
VERBOSE = 1
PALETTES = [{'name': 'palette 1',
  'predefined': {'CODE': (51, 51, 255),
                 'Overlay': (128, 128, 128)},
  'custom': [(170, 0, 0),
             (0, 170, 0),
             (0, 0, 170),
             (170, 170, 0),
             (0, 170, 170),
             (170, 0, 170),
             (128, 0, 0),
             (0, 128, 0),
             (0, 0, 128),
             (255, 255, 255),
             (17, 255, 0),
             (0, 255, 255),
             (51, 51, 51),
             (51, 51, 0),
             (0, 51, 51)],
  'default': (102, 102, 102)}]
IMGDEFAULTS = {'width': 1200,
 'height': 640,
 'background': (0, 0, 0),
 'iscale': 1.0,
 'palette': 0,
 'outlinecolor': (204, 204, 204),
 'dvcolor': (170, 170, 170),
 'font': 'Arial_Bold.ttf',
 'fontsize': 15,
 'debug': DEBUG,
 'verbose': VERBOSE}

class MDrawer(object):
    """ Class manipulating with image """
    APMARGINX, APMARGINY = (10, 10)
    APPADDINGX, APPADDINGY = (10, 10)
    PSIZE_DEFAULT = 5
    LEGENDBOX = {'width': 200,
     'height': 100}
    APMINWIDTH, APMINHEIGHT = PSIZE_DEFAULT * 10 + LEGENDBOX['width'] + APMARGINX * 3 + APPADDINGX * 4, PSIZE_DEFAULT * 10 + LEGENDBOX['height'] + APMARGINY * 3 + APPADDINGY * 4

    def __init__(self, data, **kwargs):
        self.data = data
        self.idata = IMGDEFAULTS
        self.idata.update(kwargs)
        self.debug = kwargs['debug']
        self.verbose = kwargs['verbose']
        self.psize = round(self.PSIZE_DEFAULT * float(self.idata['iscale']))
        if self.idata['width'] < self.APMINWIDTH:
            self.idata['width'] = self.APMINWIDTH
        if self.idata['height'] < self.APMINHEIGHT:
            self.idata['height'] = self.APMINHEIGHT
        self.legend = self.LEGENDBOX
        self.legend['items'] = []
        self.legend['itemindex'] = {}
        self.maxrx = int((self.idata['width'] - (self.legend['width'] + self.APMARGINX * 3 + self.APPADDINGX * 4)) / self.psize)
        self.maxry = int((self.idata['height'] - (self.APMARGINY * 2 + self.APPADDINGY * 2)) / self.psize)
        self.palette = PALETTES[self.idata['palette']]
        self.palette['custom'].reverse()
        self._processed = False

    def _draw_base(self):
        self.draw.rectangle([self.APMARGINX,
         self.APMARGINY,
         self.APMARGINX + self.APPADDINGX * 2 + self.maxrx * self.psize,
         self.APMARGINY + self.APPADDINGY * 2 + self.maxry * self.psize], fill=None, outline=self.idata['outlinecolor'])

    def _draw_legend(self):
        lx = self.APPADDINGX + self.idata['width'] - (self.APMARGINX + self.APPADDINGX * 2 + self.legend['width'])
        fs = self.idata['fontsize']
        strspacing = fs / 2
        self.draw.text([lx + self.APPADDINGX, self.APMARGINY + self.APPADDINGY], 'Legend', font=self.font)
        iofs = 1
        for litem in self.legend['items']:
            ltxt = '%s' % litem[0]
            if litem[2]:
                ltxt = '%s (%s%%)' % (litem[0], litem[2])
            ly = self.APMARGINY + self.APPADDINGY + iofs * (fs + strspacing)
            self.draw.rectangle([lx,
             ly,
             lx + fs,
             ly + fs], fill=litem[1], outline=self.idata['outlinecolor'])
            self.draw.text([lx + fs + fs, ly], ltxt, font=self.font)
            iofs += 1

        lheight = self.APPADDINGY * 2 + iofs * (fs + strspacing)
        self.draw.rectangle([lx - self.APPADDINGX,
         self.APMARGINY,
         self.idata['width'] - self.APMARGINX,
         self.APMARGINY + lheight], fill=None, outline=self.idata['outlinecolor'])
        ry = 2 * self.APMARGINY + lheight
        self.draw.text([lx + self.APPADDINGX, ry + self.APMARGINY + self.APPADDINGY], 'File Info', font=self.font)
        iofs = 1
        for fitem in self.data['File']:
            ltxt = '%s: %s' % (fitem, self.data['File'][fitem])
            ly = self.APMARGINY + self.APPADDINGY + iofs * (fs + strspacing)
            self.draw.rectangle([lx,
             ry + ly,
             lx + fs,
             ry + ly + fs], fill=None, outline=self.idata['outlinecolor'])
            self.draw.text([lx + fs + fs, ry + ly], ltxt, font=self.font)
            iofs += 1

        lheight = self.APPADDINGY * 2 + iofs * (fs + strspacing)
        self.draw.rectangle([lx - self.APPADDINGX,
         ry + self.APMARGINY,
         self.idata['width'] - self.APMARGINX,
         ry + self.APMARGINY + lheight], fill=None, outline=self.idata['outlinecolor'])

    def _pick_color(self, itemname):
        color = self.palette['default']
        if itemname in self.legend['itemindex']:
            color = self.legend['items'][self.legend['itemindex'][itemname]][1]
        elif itemname in self.palette['predefined']:
            color = self.palette['predefined'][itemname]
        elif len(self.palette['custom']) > 0:
            color = self.palette['custom'].pop()
        return color

    def _draw_data(self):
        maxel = self.maxrx * self.maxry
        maxel -= len(self.data['items'])
        granularity = int(round(float(self.data['size']) / maxel))
        if self.verbose >= 3:
            print 'Granularity: %s' % granularity
            print 'size: %s, maxel: %s' % (self.data['size'], maxel)
            print 'maxrx:maxry : %s:%s' % (self.maxrx, self.maxry)
        if self.verbose >= 5:
            print '%s' % self.data
        sum_percent_drawn = 0
        offset = 0.0
        ampl = 0
        self.data['items'].sort(key=lambda e: e[1])
        for item in self.data['items']:
            if item[2] == 0:
                continue
            color = self._pick_color(item[0])
            percent = 100 * round(float(item[2]) / self.data['size'], 4)
            sum_percent_drawn += percent
            if item[0] not in self.legend['itemindex']:
                self.legend['items'].append([item[0], color, percent])
                self.legend['itemindex'][item[0]] = len(self.legend['items']) - 1
            else:
                self.legend['items'][self.legend['itemindex'][item[0]]][2] += percent
            length = int(round(float(item[2]) / granularity))
            if length == 0 and item[2] > 0:
                length = 1
                ampl += 1
            offset = float(item[1]) / granularity + ampl
            if self.verbose >= 2:
                print 'Drawing %s (len %s, percent %s, color %s)' % (item[0],
                 length,
                 percent,
                 color)
            for step in range(length):
                ey, ex = divmod(int(offset), self.maxrx)
                ex = int(ex * self.psize + self.APMARGINX + self.APPADDINGX)
                ey = int(ey * self.psize + self.APMARGINY + self.APPADDINGY)
                self.draw.rectangle([ex,
                 ey,
                 ex + self.psize,
                 ey + self.psize], fill=color, outline=self.idata['outlinecolor'])
                offset += 1

        for pp in self.data['points']:
            color = self._pick_color(pp[0])
            if pp[0] not in self.legend['itemindex']:
                self.legend['items'].append([pp[0], color, None])
                self.legend['itemindex'][pp[0]] = len(self.legend['items']) - 1
            offset = float(pp[1]) / granularity + ampl
            ey, ex = divmod(int(offset), self.maxrx)
            ex = int(ex * self.psize + self.APMARGINX + self.APPADDINGX)
            ey = int(ey * self.psize + self.APMARGINY + self.APPADDINGY)
            self.draw.rectangle([ex,
             ey,
             ex + self.psize,
             ey + self.psize], fill=color, outline=self.idata['outlinecolor'])

        if self.verbose >= 3:
            print 'Percent drawn: %s' % sum_percent_drawn

    def _prepare(self):
        if self._processed:
            return
        self.img = Image.new('RGB', (self.idata['width'], self.idata['height']), self.idata['background'])
        self.draw = ImageDraw.Draw(self.img)
        if self.idata['font']:
            self.font = ImageFont.truetype(self.idata['font'], self.idata['fontsize'])
        else:
            self.font = ImageFont.load_default()
        self._draw_base()
        self._draw_data()
        self._draw_legend()
        self._processed = True

    def save(self, filename):
        self._prepare()
        self.img.save(filename)
        return self.img

    def show(self):
        self._prepare()
        self.img.show()

    def get_image(self):
        self._prepare()
        return self.img


def get_pe_data(pe):
    retval = {'size': 0,
     'items': [],
     'points': []}
    tsize = 0
    pe.parse_data_directories()
    ANAMES = [('MSDOS Header', 'DOS_HEADER'),
     ('NT_HEADERS', 'NT_HEADERS'),
     ('FILE_HEADER', 'FILE_HEADER'),
     ('Optional Header', 'OPTIONAL_HEADER')]
    for section in pe.sections:
        sname = re.match('([ -\xff]+)', section.Name).group(0)
        stofs = section.get_file_offset()
        retval['items'].append(('Sections Table', stofs, 40))
        ofs = section.PointerToRawData
        size = section.SizeOfRawData
        tsize += size
        if section.IMAGE_SCN_CNT_CODE:
            sname = 'CODE'
        retval['items'].append((sname, ofs, size))

    for en, an in ANAMES:
        elem = getattr(pe, an)
        ofs = elem.get_file_offset()
        size = elem.sizeof()
        if an == 'OPTIONAL_HEADER':
            size = pe.FILE_HEADER.SizeOfOptionalHeader
        elif an == 'DOS_HEADER':
            size = elem.e_cparhdr * 16
        retval['items'].append((en, ofs, size))

    lfarlc = pe.DOS_HEADER.e_lfarlc
    dosstubsize = pe.DOS_HEADER.e_lfanew - pe.DOS_HEADER.e_cparhdr * 16
    retval['items'].append(('DOS Stub', pe.DOS_HEADER.e_cparhdr * 16, dosstubsize))
    stofs = 0
    for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if stofs <= 0:
            stofs = section.get_file_offset()
            break

    imp_ofs = 0
    for imp in pe.DIRECTORY_ENTRY_IMPORT:
        imp_ofs = imp.struct.get_file_offset()
        break

    retval['items'].append(('Imports', imp_ofs, len(pe.DIRECTORY_ENTRY_IMPORT) * 20))
    retval['items'].append(('Directory Table', stofs, len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) * 8))
    ovl_start = pe.get_overlay_data_start_offset() or tsize
    owldata = pe.get_overlay() or []
    ovl_size = len(owldata)
    tsize += ovl_size
    if ovl_size > 0:
        retval['items'].append(('Overlay', ovl_start, ovl_size))
    epaddr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    retval['items'].sort(key=lambda e: e[1])
    retval['size'] = tsize
    return retval


def get_file_info(fpath):
    retval = {'File': {}}
    retval['File']['Name'] = os.path.basename(fpath)
    retval['File']['Size'] = os.path.getsize(fpath)
    return retval


def show_error(errmsg, exitcode = None):
    print '  ERROR: %s !' % errmsg
    if exitcode:
        sys.exit(exitcode)


def show_help(errmsg = None, exitcode = 0):
    htxt = '\n    Run this script with parameters:\n        python getpe.py [--help] -i inputfile [-o outputfile] [-s scale] [-w width] [-h height] [-f font]\n    '
    if errmsg:
        show_error(errmsg, exitcode=None)
    print htxt
    sys.exit(exitcode)


def get_opts(argv):
    """ Parse command-line arguments """
    retval = {'input': None,
     'output': None,
     'debug': DEBUG,
     'verbose': VERBOSE}
    try:
        opts, args = getopt.getopt(argv, 'hdv:i:o:s:w:h:f:', ['help',
         'debug',
         'verbose=',
         'input=',
         'output=',
         'scale=',
         'width=',
         'height=',
         'font='])
    except getopt.GetoptError as ger:
        show_help(errmsg='Wrong command line arguments: %s' % ger, exitcode=2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            show_help(exitcode=0)
        elif opt in ('-d', '--debug'):
            retval['debug'] = True
        elif opt in ('-v', '--verbose'):
            retval['verbose'] = arg
        elif opt in ('-i', '--input'):
            retval['input'] = arg
        elif opt in ('-o', '--output'):
            retval['output'] = arg
        elif opt in ('-s', '--scale'):
            retval['iscale'] = arg
        elif opt in ('-w', '--width'):
            retval['width'] = arg
        elif opt in ('-h', '--height'):
            retval['height'] = arg
        elif opt in ('-f', '--font'):
            retval['font'] = arg

    if retval['debug']:
        retval['verbose'] = 5
    if not retval['input']:
        show_help(errmsg='Input file is not set!', exitcode=2)
    if not retval['output']:
        retval['output'] = '%s.png' % retval['input']
    return retval


def main(argv):
    params = get_opts(argv)
    imgparams = IMGDEFAULTS
    for p in params:
        if p in imgparams:
            imgparams[p] = params[p]

    pepath = params['input']
    resultfile = params['output']
    if not os.path.exists(pepath):
        show_error(errmsg='File %s does not exists!' % pepath, exitcode=3)
    if params['verbose'] > 0:
        print 'Processing file %s to %s' % (pepath, resultfile)
    pe = pefile.PE(pepath)
    data = get_pe_data(pe)
    data.update(get_file_info(pepath))
    data['size'] = data['File']['Size']
    mdrawer = MDrawer(data, **imgparams)
    mdrawer.save(resultfile)
    if params['debug']:
        mdrawer.show()


if __name__ == '__main__':
    main(sys.argv[1:])

