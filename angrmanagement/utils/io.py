from __future__ import annotations

import os
import re
import urllib.parse

import requests

from angrmanagement.config import Conf
from angrmanagement.errors import InvalidURLError, UnexpectedStatusCodeError
from angrmanagement.logic import GlobalInfo


def isurl(uri) -> bool:
    try:
        result = urllib.parse.urlparse(uri)
        if result.scheme in ("http", "https"):
            return True
    except ValueError:
        pass

    return False


def download_url(  # pylint:disable=unused-argument
    url, parent=None, to_file: bool = True, file_path=None, use_proxies: bool = True
):
    """
    Download ``url``. With ``to_file``, save it to ``file_path``, or ask the user where when that is None, and return
    the path; otherwise return the content. ``parent`` is ignored; it was the parent of the file dialog.
    """
    if not isurl(url):
        raise TypeError("The given URL %s is not a valid URL.", url)

    r = urllib.parse.urlparse(url)
    basename = os.path.basename(r.path)
    if use_proxies and (Conf.http_proxy or Conf.https_proxy):
        proxies = {
            "http": Conf.http_proxy,
            "https": Conf.https_proxy,
        }
    else:
        proxies = None

    try:
        header = requests.head(url, allow_redirects=True, proxies=proxies)
    except requests.exceptions.InvalidURL as ex:
        raise InvalidURLError from ex

    if header.status_code != 200:
        raise UnexpectedStatusCodeError(header.status_code)

    if "content-disposition" in header.headers:
        # update the base name
        fnames = re.findall("filename=(.+)", header.headers["content-disposition"])
        if fnames:
            basename = fnames[0].strip('"')

    if to_file:
        # save the content to a file and then return the path
        if file_path is None:
            target_path = GlobalInfo.ui_services.pick_save_file("Download a file to...", basename, "Any file (*);")
            if not target_path:
                # terminated
                return None
        else:
            target_path = file_path

        # downloading it
        req = requests.get(url, allow_redirects=True, proxies=proxies)
        if req.status_code != 200:
            raise UnexpectedStatusCodeError(req.status_code)

        with open(target_path, "wb") as f:
            f.write(req.content)
        return target_path

    else:
        # download the content and return as a blob
        # downloading it
        req = requests.get(url, allow_redirects=True, proxies=proxies)
        if req.status_code != 200:
            raise UnexpectedStatusCodeError(req.status_code)

        return req.content
