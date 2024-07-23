# pylint:disable=no-self-use
from __future__ import annotations

import unittest

from angrmanagement.data.tagged_interval_map import TaggedIntervalMap


class TaggedIntervalMapTests(unittest.TestCase):
    """
    Test cases for TaggedIntervalMap
    """

    def test_non_overlapping(self):
        im = TaggedIntervalMap()
        im.add(0, 100, 1)
        im.add(100, 100, 2)
        im.add(200, 100, 4)
        assert im._map == {0: 1, 100: 2, 200: 4, 300: 0}

    def test_non_overlapping_with_gaps(self):
        im = TaggedIntervalMap()
        im.add(0, 100, 1)
        im.add(200, 100, 2)
        im.add(400, 100, 4)
        assert im._map == {0: 1, 100: 0, 200: 2, 300: 0, 400: 4, 500: 0}

    def test_insertion(self):
        im = TaggedIntervalMap()
        im.add(0, 100, 1)
        im.add(25, 50, 2)
        assert im._map == {0: 1, 25: 3, 75: 1, 100: 0}

    def test_insertion_already_covered(self):
        im = TaggedIntervalMap()
        im.add(0, 100, 1)
        im.add(20, 20, 1)
        assert im._map == {0: 1, 100: 0}

    def test_overlapping(self):
        im = TaggedIntervalMap()
        im.add(0, 100, 1)
        im.add(50, 100, 2)
        im.add(100, 100, 4)
        assert im._map == {0: 1, 50: 3, 100: 6, 150: 4, 200: 0}

    def test_merge_middle(self):
        im = TaggedIntervalMap()
        im.add(0, 100, 1)
        im.add(200, 100, 1)
        im.add(100, 100, 1)
        assert im._map == {0: 1, 300: 0}

        im = TaggedIntervalMap()
        im.add(0, 10, 2)
        im.add(10, 100, 1)
        im.add(200, 100, 1)
        im.add(300, 10, 2)
        im.add(100, 100, 1)
        assert im._map == {0: 2, 10: 1, 300: 2, 310: 0}

    def test_merge_left(self):
        im = TaggedIntervalMap()
        im.add(0, 100, 1)
        im.add(100, 100, 1)
        assert im._map == {0: 1, 200: 0}
        im.add(200, 100, 1)
        assert im._map == {0: 1, 300: 0}

    def test_merge_right(self):
        im = TaggedIntervalMap()
        im.add(200, 100, 1)
        im.add(100, 100, 1)
        im.add(0, 100, 1)
        assert im._map == {0: 1, 300: 0}

    def test_binning(self):
        im = TaggedIntervalMap(4)
        im.add(2, 4, 1)
        assert im._map == {0: 1, 16: 0}
        im.add(15, 3, 2)
        assert im._map == {0: 3, 16: 2, 32: 0}

    def test_empty_iteration(self):
        im = TaggedIntervalMap()
        assert not list(im.irange())
        assert not list(im.irange(0, 100))

    def test_unbounded_iteration(self):
        im = TaggedIntervalMap()
        im.add(100, 100, 2)
        assert list(im.irange()) == [(100, 100, 2)]
        im.add(200, 100, 4)
        assert list(im.irange()) == [(100, 100, 2), (200, 100, 4)]
        im.add(0, 200, 1)
        assert list(im.irange()) == [(0, 100, 1), (100, 100, 3), (200, 100, 4)]

    def test_bounded_iteration(self):
        im = TaggedIntervalMap()
        im.add(100, 100, 1)
        im.add(150, 100, 2)
        im.add(300, 50, 4)
        assert not list(im.irange(0, 0))
        assert list(im.irange(0, 100)) == [(100, 50, 1)]
        assert list(im.irange(75, 175)) == [(100, 50, 1), (150, 50, 3)]
        assert list(im.irange(None, 175)) == [(100, 50, 1), (150, 50, 3)]
        assert list(im.irange(75, 299)) == [(100, 50, 1), (150, 50, 3), (200, 50, 2), (250, 50, 0)]
        assert list(im.irange(175, None)) == [(150, 50, 3), (200, 50, 2), (250, 50, 0), (300, 50, 4)]
        assert not list(im.irange(351, 400))


if __name__ == "__main__":
    unittest.main()
