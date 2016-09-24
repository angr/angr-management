
from atom.api import List, Typed, ForwardTyped, observe
from enaml.widgets.api import Container
from enaml.widgets.frame import Frame, ProxyFrame
from enaml.core.declarative import d_

class ProxyGraph(ProxyFrame):
    declaration = ForwardTyped(lambda: Graph)


class Graph(Frame):
    #: The edges (as names) of the Graph
    edges = d_(List())

    #: The "selected" node that should be visible
    selected = d_(Typed(str))

    proxy = Typed(ProxyGraph)

    hug_width = 'weak'
    hug_height = 'weak'

    def child_added(self, child):
        super(Graph, self).child_added(child)
        # print "got a child! %s" % child
        # if hasattr(child, 'path'):
        #     print "has id: %s" % child.path.path_id
        if isinstance(child, Container):
            self.request_relayout()

    @observe('edges')
    def _update(self, change):
        self.request_relayout()

    @observe('selected')
    def _selected_update(self, change):
        if self.proxy is not None:
            self.proxy.show_selected()
