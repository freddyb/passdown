
MIMETYPES_AUDIO = ['audio/flac', 'audio/mp4a-latm', 'audio/mpa-robust', 'audio/mpeg', 'audio/mpegurl', 'audio/ogg', 'audio/x-aiff', 'audio/x-gsm', 'audio/x-ms-wma', 'audio/x-ms-wax', 'audio/x-pn-realaudio-plugin', 'audio/x-pn-realaudio', 'audio/x-realaudio', 'audio/x-wav', 'application/ogg']
MIMETYPES_VIDEO = ['video/3gpp', 'video/mpeg', 'video/mp4', 'video/quicktime', 'video/ogg', 'video/webm', 'video/x-flv', 'video/x-la-asf', 'video/x-ms-asf', 'video/x-ms-wm', 'video/x-ms-wmv', 'video/x-ms-wmx', 'video/x-ms-wvx', 'video/x-msvideo', 'video/x-matroska', 'video/x-f4v']

MIMETYPES = MIMETYPES_AUDIO + MIMETYPES_VIDEO

from re import match, IGNORECASE
from time import strftime # for filenames
from os.path import isdir, exists # dito

class Http:
    regex = 'HTTP\/\d\.\d 200 OK'
    name = "HTTP"
    def __init__(self, s_stream, c_stream):
        header, body = s_stream.split("\r\n\r\n", 1)
        header_fields = header.split("\r\n")
        save = False
        for field in header_fields:
            """ XXX this block needs tidying
                let's add support for compressed files
            """
            m = match('Content-type: (.*)', field, IGNORECASE)
            if m:
                filetype = m.group(1)
                if ';' in filetype:
                    filetype = filetype.split(";")[0].strip()
                    # case: Content-Type: audio/mpeg;charset=UTF-8
                if filetype in MIMETYPES:
                    save = True
        if save:
            self.savefile(body, filetype, c_stream)

    def savefile(self, body, filetype, c_stream):
        fname = 'output/%s_%s_%s' % (filetype.split("/")[0], strftime('%Y%m%d_%H-%M'),  self.getfilename(c_stream))
        # e.g. output/audio_20110703_20-03_stream.php
        while exists(fname):
            fname += '1' # append 1 if file exists :D

        file(fname, 'wb').write(body)
        print "Written to", fname

    def getfilename(self, c_stream):
        req = c_stream.split("\r\n")[0]
        method, path, version = req.split()
        fname = path.split("/")[-1].split("?")[0] # discard parameters
        return fname[:80] # only first 80 chars
