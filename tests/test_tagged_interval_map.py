# pylint:disable=no-self-use
from __future__ import annotations

import random
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

    def test_add_many_matches_add(self):
        rng = random.Random(0)
        for trial in range(400):
            nbits = rng.choice([0, 0, 2, 4])
            seq = TaggedIntervalMap(nbits)
            batched = TaggedIntervalMap(nbits)
            span = rng.choice([64, 512, 4096])
            for _ in range(rng.randint(1, 4)):
                batch = [
                    (rng.randrange(span), rng.choice([0, 1, 3, 16, 100]), rng.choice([1, 1, 2, 3, 4, 5]))
                    for _ in range(rng.randint(0, 40))
                ]
                for addr, size, tags in batch:
                    seq.add(addr, size, tags)
                batched.add_many(batch)
                assert batched._map == seq._map, (trial, nbits, batch)

    def test_add_many_coalesced_pieces(self):
        im = TaggedIntervalMap()
        im.add_many([(100, 100, 1), (0, 100, 1), (150, 100, 2), (300, 0, 4)])
        assert im._map == {0: 1, 150: 3, 200: 2, 250: 0}
        assert TaggedIntervalMap.coalesce([(10, 5, 1), (0, 10, 1), (12, 10, 2)]) == [
            (0, 12, 1),
            (12, 3, 3),
            (15, 7, 2),
        ]
        # pieces coalesced at full resolution give a binned map the same result as the raw intervals
        raw = [(2, 4, 1), (15, 3, 2), (40, 1, 1)]
        im_raw = TaggedIntervalMap(4)
        im_raw.add_many(raw)
        im_pieces = TaggedIntervalMap(4)
        im_pieces.add_many(TaggedIntervalMap.coalesce(raw))
        assert im_raw._map == im_pieces._map == {0: 3, 16: 2, 32: 1, 48: 0}


if __name__ == "__main__":
    unittest.main()
