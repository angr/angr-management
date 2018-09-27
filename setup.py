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
    version='7.8.9.26',
    python_requires='<3.0',
    description='GUI for angr',
    url='https://github.com/angr/angr-management',
    packages=packages,
    package_data={
    },
    install_requires=[
        'angr==7.8.9.26',
        'pygments==2.2.0',
        'websocket-client==0.53.0',
        'qtconsole==4.4.1',
        'ipython==5.8.0',
        'pyzmq==17.1.2',
        'PySide==1.2.4',
        'pyqode.core==2.11.0',
        'pyqode.python==1.10.0',
    ]
)
