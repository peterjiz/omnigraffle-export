#!/usr/bin/env python

import hashlib
import optparse
import os
import pathlib
import subprocess
import sys
import tempfile
import shutil

from Foundation import NSURL, NSMutableDictionary
from Quartz import PDFKit

from omnigraffle_export.omnigraffle import *
# from omnigraffle import *

import re, shutil, tempfile

# https://stackoverflow.com/questions/4427542/how-to-do-sed-like-text-replace-with-python
def sed_inplace(filename, pattern, repl):
    '''
    Perform the pure-Python equivalent of in-place `sed` substitution: e.g.,
    `sed -i -e 's/'${pattern}'/'${repl}' "${filename}"`.
    '''
    # For efficiency, precompile the passed regular expression.
    pattern_compiled = re.compile(pattern)

    # For portability, NamedTemporaryFile() defaults to mode "w+b" (i.e., binary
    # writing with updating). This is usually a good thing. In this case,
    # however, binary writing imposes non-trivial encoding constraints trivially
    # resolved by switching to text writing. Let's do that.
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        with open(filename) as src_file:
            for line in src_file:
                tmp_file.write(pattern_compiled.sub(repl, line))

    # Overwrite the original file with the munged temporary file in a
    # manner preserving file attributes (e.g., permissions).
    shutil.copystat(filename, tmp_file.name)
    shutil.move(tmp_file.name, filename)

def export(source, target, canvasname=None, format='pdf_tex', debug=False, force=False):
    # logging
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')

    # target
    target = os.path.abspath(target)

    # mode
    export_all = os.path.isdir(target)

    # determine the canvas
    if not export_all:
        # guess from filename
        if not canvasname:
            canvasname = os.path.basename(target)
            canvasname = canvasname[:canvasname.rfind('.')]

        if not canvasname or len(canvasname) == 0:
            print("Without canvas name, the target (-t) " "must be a directory", file=sys.stderr)
            sys.exit(1)

    # determine the format
    if not export_all:
        # guess from the suffix
        if not format:
            format = target[target.rfind('.') + 1:]

    if not format or len(format) == 0:
        format = 'pdf'
    else:
        format = format.lower()

    # check source
    if not os.access(source, os.R_OK):
        print("File: %s could not be opened for reading" % source, file=sys.stderr)
        sys.exit(1)


    if format == "pdf_tex":
        tmp_source = pathlib.Path(source).parent / "tmp_{}".format(str(pathlib.Path(source).name))
        shutil.copyfile(source, tmp_source)

        og = OmniGraffle()
        schema = og.open(tmp_source)
        canvasname = schema.get_canvas_list()[0]

        # First Export to PDF
        if export_all:
            namemap = lambda c, f: '%s.%s' % (c, f) if f else c

            for c in schema.get_canvas_list():
                canvas_file = c.replace(":", "")
                canvas_file = canvas_file.replace("/", "")

                tmp_target = str(pathlib.Path(target).parent / "pdf_tex_{}".format(namemap(canvas_file, format)))
                logging.debug("Exporting `%s' into `%s' as %s" % (c, tmp_target, format))
                export_one(schema, tmp_target, canvasname, "pdf", force)
                # Then create pdf_tex(s) using inkscape
                targetPDF_TEXFile = str(pathlib.Path(target).parent / "{}_tex.pdf".format(namemap(canvas_file, format)))
                cmdString = "inkscape -D {} -o {} --export-latex".format(tmp_target, targetPDF_TEXFile)
                subprocess.run(cmdString, shell=True, check=True, capture_output=True)

                pattern = r"\\put\(0,0\)\{\\includegraphics\[width\=\\unitlength,page\=\b(?![01]\b)\d{1,4}\b\]\{" + targetPDF_TEXFile + "\}\}" + "%"
                sed_inplace("{}_tex".format(targetPDF_TEXFile), pattern, "")

                # Then export graphics only pdf(s)
                export_one(schema, targetPDF_TEXFile, canvasname, "pdf", force, stripText=True)
                try:
                    os.remove(tmp_target)
                except Exception as e:
                    pass
        else:
            tmp_target = str(pathlib.Path(target).parent / "pdf_tex_{}.pdf".format(pathlib.Path(target).stem))
            targetPDF_TEXFile = str(pathlib.Path(target).parent / "{}_tex.pdf".format(str(pathlib.Path(target).stem)))
            targetPDF_TEXFile_filename = str(pathlib.Path(targetPDF_TEXFile).name)
            export_one(schema, tmp_target, canvasname, "pdf", force)
            # Then create pdf_tex(s) using inkscape
            cmdString = "inkscape -D {} -o {} --export-latex".format(tmp_target, targetPDF_TEXFile)
            subprocess.run(cmdString, shell=True, check=True, capture_output=True)

            pattern = r"\\put\(0,0\)\{\\includegraphics\[width\=\\unitlength,page\=\b(?![01]\b)\d{1,4}\b\]\{" + targetPDF_TEXFile_filename + "\}\}" + "%"
            sed_inplace("{}_tex".format(targetPDF_TEXFile), pattern, "")
            # Then export graphics only pdf(s)
            export_one(schema, targetPDF_TEXFile, canvasname, "pdf", force, stripText=True)
            try:
                os.remove(tmp_target)
            except Exception as e:
                pass

        del schema
        try:
            os.remove(tmp_source)
        except Exception as e:
            pass

        try:
            os.rmdir(tmp_source)
        except Exception as e:
            pass

    else:
        og = OmniGraffle()
        schema = og.open(source)
        canvasname = schema.get_canvas_list()[0]

        if export_all:
            namemap = lambda c, f: '%s.%s' % (c, f) if f else c

            for c in schema.get_canvas_list():
                canvas_file = c.replace(":", "")
                canvas_file = canvas_file.replace("/", "")

                targetfile = os.path.join(os.path.abspath(target), namemap(canvas_file, format))
                logging.debug("Exporting `%s' into `%s' as %s" % (c, targetfile, format))
                export_one(schema, targetfile, c, format, force)
        else:
            export_one(schema, target, canvasname, format, force)


def export_one(schema, filename, canvasname, format='pdf', force=False, stripText=False):
    def _checksum(filepath):
        assert os.path.isfile(filepath), '%s is not a file' % filepath

        # set new_md5_shellout to do shell script "md5 " & quoted form of pdfPath
        # set new_md5 to second item of my splitText(new_md5_shellout, ("= "))
        md5Out = subprocess.run("md5 {}".format(filepath), shell=True, check=True, capture_output=True).stdout
        md5OutStr = str(md5Out).split("= ", -1)[1].split("\\n")[0]


        # c = hashlib.md5()
        # with open(filepath, 'rb') as f:
        #     for chunk in iter(lambda: f.read(128), ''):
        #         c.update(chunk)
        #
        # return c.hexdigest()

        return md5OutStr

    def _checksum_pdf(filepath):
        assert os.path.isfile(filepath), '%s is not a file' % filepath

        url = NSURL.fileURLWithPath_(filepath)
        pdfdoc = PDFKit.PDFDocument.alloc().initWithURL_(url)

        assert pdfdoc != None

        chsum = None
        attrs = pdfdoc.documentAttributes()
        if PDFKit.PDFDocumentSubjectAttribute in attrs:
            chksum = pdfdoc.documentAttributes()[PDFKit.PDFDocumentSubjectAttribute]
        else:
            return None

        if not chksum.startswith(OmniGraffleSchema.PDF_CHECKSUM_ATTRIBUTE):
            return None
        else:
            return chksum[len(OmniGraffleSchema.PDF_CHECKSUM_ATTRIBUTE):]

    def _compute_canvas_checksum(canvasname):
        tmpfile = tempfile.mkstemp(suffix='.png')[1]
        os.unlink(tmpfile)

        export_one(schema, tmpfile, canvasname, 'png')

        try:
            chksum = _checksum(tmpfile)
            return chksum
        finally:
            os.unlink(tmpfile)

    # checksum
    chksum = None
    if os.path.isfile(filename) and not force:
        existing_chksum = _checksum(filename) if format != 'pdf' else _checksum_pdf(filename)

        new_chksum = _compute_canvas_checksum(canvasname)

        if existing_chksum == new_chksum and existing_chksum != None:
            logging.debug('Not exporting `%s` into `%s` as `%s` - canvas has not been changed' % (canvasname, filename, format))
            return False
        else:
            chksum = new_chksum

    elif format == 'pdf':
        chksum = _compute_canvas_checksum(canvasname)

    try:
        schema.export(canvasname, filename, format=format, stripText=stripText)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return False

    # update checksum
    if format == 'pdf':
        # save the checksum
        url = NSURL.fileURLWithPath_(filename)
        pdfdoc = PDFKit.PDFDocument.alloc().initWithURL_(url)
        attrs = NSMutableDictionary.alloc().initWithDictionary_(pdfdoc.documentAttributes())

        attrs[PDFKit.PDFDocumentSubjectAttribute] = '%s%s' % (OmniGraffleSchema.PDF_CHECKSUM_ATTRIBUTE, chksum)

        pdfdoc.setDocumentAttributes_(attrs)
        pdfdoc.writeToFile_(filename)

    return True


def main():
    usage = "Usage: %prog [options] <source> <target>"
    parser = optparse.OptionParser(usage=usage)

    parser.add_option('-c', help='canvas name. If not given it will be guessed from ' 'the target filename unless it is a directory.', metavar='NAME', dest='canvasname')
    parser.add_option('-f', help='format (one of: pdf, png, svg, eps). Guessed ' 'from the target filename suffix unless it is a ' 'directory. Defaults to pdf', metavar='FMT', dest='format')
    parser.add_option('--force', action='store_true', help='force the export', dest='force')
    parser.add_option('--debug', action='store_true', help='debug', dest='debug')

    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.print_help()
        sys.exit(1)

    (source, target) = args

    export(source, target, options.canvasname, options.format, options.debug, options.force)


if __name__ == '__main__':
    main()
