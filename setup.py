try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='angr-management',
    version='8.18.10.25',
    description='GUI for angr',
    url='https://github.com/angr/angr-management',
    packages=packages,
    package_data={
    },
    install_requires=[
        'angr==8.18.10.25',
        'pygments',
        'websocket-client',
        'qtconsole',
        'ipython',
        'pyzmq',
        'PySide2',
    ]
)
