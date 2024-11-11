Events
======

The ObjectContainer
^^^^^^^^^^^^^^^^^^^

angr management uses a class called ObjectContainer to implement a pub-sub model
and synchronize changing object references. Let's use ``instance.project`` as an
example. This is an ObjectContainer that contains the current project. You can
use it in every way that you would normally use a project - you can access
``project.factory``, ``project.kb``, etc. However, it also has two very
important features that are helpful for building UIs.

First, the pub-sub model. You can subscribe to changes to this object by calling
``instance.project.am_subscribe(callback)``. Then, you can notify listeners of
changes by calling ``instance.project.am_event()``. Note that events are NEVER
automatically triggered - you must call ``am_event`` in order to trigger the
callbacks. One useful feature of this model is that you can provide arbitrary
keyword arguments to ``am_event``, and they will be passed on to each callback.
This means that you should always have your callbacks take ``**kwargs`` in order
to account for unknown parameters. This feature is particularly useful to
prevent feedback loops - if you ever find yourself in a situation where you need
to broadcast an event from your callback, you can add an argument that you can
use as a flag not to recurse any further.

Next, object reference mutability. Let's say you have a widget that displays
information about the project. Following the principle of least access, you
should only provide as much information as is necessary to do the job - in this
case, just the project object. If you provide the basic project object, this
will cause issues when a new project is loaded. Notably, there will be a
dangling reference held to the original project, preventing it from being
garbage collected, and the widget will not update, continuing to show the old
project's information. Now, if you provide the project's ObjectContainer, a new
project can be created and inserted into the container and the reference will
instantly be available to your widget. If you ever wanted to load a new project
yourself, all you have to do is assign to ``instance.project.am_obj`` and then
send off an event. Combined with the event publication model, this provides an
efficient way to build responsive UIs that follow the principle of least access.

One important way that you can't use the object container the same way that you
would a normal object is that ``is None`` will obviously not work. To resolve
this, you can use ``instance.project.am_none`` - this will be True when no
project is loaded.

One interesting feature of the ObjectContainer is that they can nest. If you
have a container which contains a container which contains an object, any events
sent to the inner container will also be sent to subscribers to the outer
container. This allows patterns such as the list of SimStates actually
containing a list of ObjectContainers which contain states, and the "current
state" container actually contains one of these containers. The result of this
is that UI elements can either subscribe to the current state, no matter

A full list of standard ObjectContainers that can be found in the `instance
__init__ method
<https://github.com/angr/angr-management/blob/master/angrmanagement/data/instance.py>`_.
There are more containers floating around for synchronizing on non-global
elements - for example, the current state of the disassembly view is
synchronized through its InfoDock object. Given a disassembly view instance, you
can subscribe to, for example, its current selected instructions through
``view.infodock.selected_insns``.
