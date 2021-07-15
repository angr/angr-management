import os
import json
import logging

from ..utils.env import is_pyinstaller, app_root

_l = logging.getLogger(name=__name__)


class LibraryDocs:
    """
    Implements the manager of library docs.
    """
    def __init__(self):
        self.func_docs = [ ]

    def load_func_docs(self, path):
        if not os.path.isabs(path):
            if is_pyinstaller():
                path = os.path.join(app_root(), path)
            else:
                path = os.path.join(app_root(), "..", path)
        path = os.path.normpath(path)
        _l.info("Loading library docs from %s.", path)
        docs = [ ]
        if os.path.isdir(path):
            for filename in os.listdir(path):
                if filename.endswith(".json"):
                    jpath = os.path.join(path, filename)
                    with open(jpath, "r") as jfile:
                        data = json.load(jfile)
                        docs.append(data)

        self.func_docs = docs

    def get_docstring_for_func_name(self, func_name):
        for library in self.func_docs:
            for func_dict in library:
                if "name" not in func_dict.keys():
                    continue
                if "description" not in func_dict.keys():
                    continue
                names = func_dict["name"]
                name_list = names.split(",")
                for name in name_list:
                    name = name.strip()
                    if func_name == name:
                        doc_string = func_dict["description"]
                        url = "http://"
                        ftype = "<>"
                        if "url" in func_dict.keys():
                            url = func_dict["url"]
                        if "type" in func_dict.keys():
                            ftype = func_dict["type"]
                        return doc_string, url, ftype
        return None
