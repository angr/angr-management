try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

import platform
if platform.python_implementation() != 'CPython':
    raise Exception("angr-management must be run with CPython. PyPy cannot work right now.")

setup(
    name='angr-management',
    version='8.19.4.5',
    description='GUI for angr',
    url='https://github.com/angr/angr-management',
    packages=packages,
    package_data={
        'angrmanagement': [
            'resources/fonts/*.ttf',
            'resources/images/*',
        ]
    },
    install_requires=[
        'angr==8.19.4.5',
        'websocket-client',
        'qtconsole',
        'ipython',
        'pyzmq',
        'shiboken2',
        'PySide2',
        'toml',
        'pyxdg',
    ]
)
