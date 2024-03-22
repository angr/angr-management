from __future__ import annotations


class EdgeSort:
    DIRECT_JUMP = 0
    TRUE_BRANCH = 1
    FALSE_BRANCH = 2
    BACK_EDGE = 3
    EXCEPTION_EDGE = 4


class Edge:
    def __init__(self, src, dst, sort=EdgeSort.DIRECT_JUMP) -> None:
        self.src = src
        self.dst = dst

        self.start_index = None
        self.max_start_index = None
        self.end_index = None
        self.max_end_index = None

        self.points = []
        self.moves = []
        self.coordinates = []
        self.sort = sort

    def add_point(self, col, row, index) -> None:
        self.points.append((col, row, index))

    def add_move(self, move) -> None:
        self.moves.append(move)

    def add_coordinate(self, x, y) -> None:
        if len(self.coordinates) >= 2:
            coord_a, coord_b = self.coordinates[-2], self.coordinates[-1]
            if coord_b[0] == coord_a[0] == x:
                # it moves vertically
                # replace coord_b
                self.coordinates[-1] = (x, y)
                return
            elif coord_b[1] == coord_a[1] == y:
                # it moves horizontally
                # replace coord b
                self.coordinates[-1] = (x, y)
                return

        self.coordinates.append((x, y))

    @property
    def first_move(self):
        if self.moves:
            return self.moves[0]

        return 1  # NO_MOVE

    @property
    def last_move(self):
        if self.moves:
            return self.moves[-1]

        return 1  # NO_MOVE

    def __repr__(self) -> str:
        return "<Edge between %s and %s, %d coordinates>" % (self.src, self.dst, len(self.coordinates))
