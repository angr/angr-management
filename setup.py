import platform

from setuptools import setup, find_packages

if platform.python_implementation() != 'CPython':
    raise Exception("angr-management must be run with CPython. PyPy cannot work right now.")

setup(
    name='angr-management',
    version='9.1.gitrolling',
    python_requires='>=3.6',
    description='GUI for angr',
    url='https://github.com/angr/angr-management',
    packages=find_packages(),
    package_data={
        'angrmanagement': [
            'resources/fonts/*.ttf',
            'resources/images/*',
        ]
    },
    entry_points={
        "console_scripts": [
            "angr-management = angrmanagement.__main__:main",
        ]
    },
    install_requires=[
        'angr[angrDB]==9.1.gitrolling',
        'websocket-client',
        'qtconsole',
        'ipython',
        'pyzmq',
        'PySide2>5.14.2.1',
        'toml',
        'pyxdg',
        'jupyter-client',
        'requests[socks]',
        'pyqodeng.core',
        'qtterm',
        'getmac',
        'QtAwesome',
    ],
    extras_require={
        'bintrace': ['bintrace']
    }
)
