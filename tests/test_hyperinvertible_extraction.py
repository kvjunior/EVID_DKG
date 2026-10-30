import itertools
import unittest

from accountable_dkg.crypto.pedersen import Q
from accountable_dkg.protocol.extraction import cauchy_extraction_matrix, extract_coefficients


def determinant(matrix):
    work = [list(row) for row in matrix]
    result = 1
    for column in range(len(work)):
        pivot = next((row for row in range(column, len(work)) if work[row][column]), None)
        if pivot is None:
            return 0
        if pivot != column:
            work[column], work[pivot] = work[pivot], work[column]
            result = -result
        result = result * work[column][column] % Q
        inverse = pow(work[column][column], -1, Q)
        for row in range(column + 1, len(work)):
            factor = work[row][column] * inverse % Q
            for item in range(column, len(work)):
                work[row][item] = (work[row][item] - factor * work[column][item]) % Q
    return result % Q


class HyperinvertibleExtractionTests(unittest.TestCase):
    def test_every_small_square_minor_of_cauchy_matrix_is_invertible(self):
        matrix = cauchy_extraction_matrix(3, 4)
        for size in (1, 2, 3):
            for rows in itertools.combinations(range(3), size):
                for columns in itertools.combinations(range(4), size):
                    minor = tuple(tuple(matrix.rows[row][column] for column in columns) for row in rows)
                    self.assertNotEqual(determinant(minor), 0)

    def test_split_extraction_uses_t_plus_one_first_and_ell_minus_t_second_rows(self):
        matrix = cauchy_extraction_matrix(3, 4)
        first = (2, 3, 5, 7)
        second = (11, 13, 17, 19)
        actual = extract_coefficients(matrix, first, second, faults=1, degree=2)
        self.assertEqual(actual, matrix.apply(first)[:2] + matrix.apply(second)[2:3])


if __name__ == "__main__":
    unittest.main()
