Overview
========

.. warning::
   Please note that the documentation and the API for angr management are highly
   in-flux. You will need to spend time reading the source code. Grep is your
   friend. If you have questions, please ask in the angr Discord server.

   If you build something which uses an API and you want to make sure it doesn't
   break, you can contribute a testcase for the API!


Main Window, Workspace, and Instance
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* First, the ``main_window``. This is the ``QMainWindow`` instance for the
  application. It contains basic functions that correspond to top-level buttons,
  such as loading a binary.
* Next, the ``workspace``. This is a light object which coordinates the UI
  elements and manages the tabbed environment. You can use it to access any
  analysis-related GUI element, such as the disassembly view.
* Finally, the ``instance``. This is angr management's data model. It contains
  mechanisms for synchronizing components on shared data sources, as well as
  logic for creating long-running jobs.

``workspace`` is also available as an attribute on ``main_window`` and
``instance`` is available as an attribute on ``workspace``. If you are
programming in a namespace where none of these objects are available, you can
import the ``angrmanagment.logic.GlobalInfo`` object, which contains a reference
to ``main_window``.
