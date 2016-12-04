from distutils.core import setup

setup(
    name='angr-management',
    version='5.6.12.3',
    description='GUI for angr',
    url='https://github.com/angr/angr-management',
    packages=['angrmanagement', 'angrmanagement.ui', 'angrmanagement.data', 'angrmanagement.qt',
              'angrmanagement.utils', 'angrmanagement.widgets'],
    package_data={
        'angrmanagement.ui': ['*.enaml']
    },
    install_requires=[
        'angr',
        'enaml==0.9.8',
        'pygments',
        'websocket-client',
        'grandalf',
        'qtconsole',
        'ipython',
        'pyzmq',
        'PySide',
        'pygraphviz',
    ]
)
