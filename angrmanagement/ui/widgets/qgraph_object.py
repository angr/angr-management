from PySide6.QtWidgets import QGraphicsItem


class QCachedGraphicsItem(QGraphicsItem):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self._cached_bounding_rect = None
        self._cached_device_pixel_ratio = None

    def clear_cache(self):
        self.prepareGeometryChange()
        self._cached_bounding_rect = None
        self._cached_device_pixel_ratio = None

    def refresh(self):
        pass

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    def recalculate_size(self):
        self.prepareGeometryChange()
        self._cached_device_pixel_ratio = None
        self._cached_bounding_rect = self._boundingRect()

    def boundingRect(self):
        if self._cached_bounding_rect is None:
            self._cached_bounding_rect = self._boundingRect()
        return self._cached_bounding_rect

    def _boundingRect(self):
        raise NotImplementedError

    def _boundingRectAdjusted(self):
        # adjust according to devicePixelRatioF
        return self._boundingRect()
