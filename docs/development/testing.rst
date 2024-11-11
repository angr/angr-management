Testing
=======

Writing tests
^^^^^^^^^^^^^

Look at the `existing tests
<https://github.com/angr/angr-management/tree/master/tests>`_ for examples.
Generally, you can test UI components by creating the component and driving
input to it via QTest. You can create a headless MainWindow instance by passing
``show=False`` to its constructor - this will also get you access to a workspace
and an instance.
