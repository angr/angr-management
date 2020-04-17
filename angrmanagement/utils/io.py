
import re
import os
import urllib.parse

import requests

from PySide2.QtWidgets import QFileDialog

from ..errors import InvalidURLError, UnexpectedStatusCodeError


def isurl(uri):
    try:
        result = urllib.parse.urlparse(uri)
        if result.scheme in ("http", "https"):
            return True
    except ValueError:
        pass

    return False


def download_url(url, parent=None, to_file=True, file_path=None):

    if not isurl(url):
        raise TypeError("The given URL %s is not a valid URL.", url)

    r = urllib.parse.urlparse(url)
    basename = os.path.basename(r.path)

    try:
        header = requests.head(url, allow_redirects=True)
    except requests.exceptions.InvalidURL:
        raise InvalidURLError()

    if header.status_code != 200:
        raise UnexpectedStatusCodeError(header.status_code)

    if 'content-disposition' in header.headers:
        # update the base name
        fnames = re.findall("filename=(.+)", header.headers['content-disposition'])
        if fnames:
            basename = fnames[0].strip('"')

    if to_file:
        # save the content to a file and then return the path
        if file_path is None:
            filename, folder = QFileDialog.getSaveFileName(
                parent,
                "Download a file to...",
                basename,
                "Any file (*);"
            )
            if filename and folder:
                target_path = os.path.join(folder, filename)
            else:
                # terminated
                return None
        else:
            target_path = file_path

        # downloading it
        req = requests.get(url, allow_redirects=True)
        if req.status_code != 200:
            raise UnexpectedStatusCodeError(req.status_code)

        with open(target_path, "wb") as f:
            f.write(req.content)
        return target_path

    else:
        # download the content and return as a blob
        # downloading it
        req = requests.get(url, allow_redirects=True)
        if req.status_code != 200:
            raise UnexpectedStatusCodeError(req.status_code)

        return req.content
