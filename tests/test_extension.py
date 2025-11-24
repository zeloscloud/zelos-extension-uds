"""Tests showcasing the Zelos checker framework.

This file demonstrates all available checker operators.
Users can run these tests to see the "checkerboard" output format.
"""


def test_checker_equality(check) -> None:
    """Equality and inequality operators."""
    check.that(10, "==", 10)
    check.that(10, "is equal to", 10)
    check.that("hello", "!=", "goodbye")


def test_checker_comparison(check) -> None:
    """Comparison operators."""
    check.that(10, ">", 5)
    check.that(10, ">=", 10)
    check.that(5, "<", 10)
    check.that(5, "<=", 10)


def test_checker_membership(check) -> None:
    """Membership operators."""
    check.that(2, "in", [1, 2, 3])
    check.that(4, "not in", [1, 2, 3])
    check.that([1, 2, 3], "contains", 2)


def test_checker_approximation(check) -> None:
    """Approximation operators (math.isclose and pytest.approx)."""
    check.that(3.14159, "is close to", 3.14, kwargs={"rel_tol": 0.01})
    check.that(3.14159, "~=", 3.14, kwargs={"rel": 0.01})


def test_checker_strings(check) -> None:
    """String operators."""
    check.that("hello world", "starts with", "hello")
    check.that("hello world", "ends with", "world")
    check.that("hello world", "contains", "world")


def test_checker_collections(check) -> None:
    """Collection operators."""
    check.that([1, 2, 3], "has length", 3)
    check.that([], "is empty")


def test_checker_numeric(check) -> None:
    """Numeric operators."""
    check.that(42, "is positive")
    check.that(-42, "is negative")
    check.that(10, "is divisible by", 5)


def test_checker_boolean(check) -> None:
    """Boolean checking (strict, not truthy/falsy)."""
    check.that(True, "is true")
    check.that(False, "is false")


def test_checker_types(check) -> None:
    """Type checking operators."""
    check.that("hello", "is instance of", str)
    check.that(42, "is instance of", int)


def test_checker_attributes(check) -> None:
    """Object attribute checking."""

    class Example:
        def __init__(self):
            self.value = 42

    obj = Example()
    check.that(obj, "has attribute", "value")
    check.that("hello", "has attribute", "upper")
