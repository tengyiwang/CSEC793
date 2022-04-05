from __future__ import division
from __future__ import print_function

import random
import functools

# 12th Mersenne Prime
# too large and all the ciphertext is large; too small and
# security is compromised)


class Shamir():
    _PRIME = None  #
    # 13th Mersenne Prime is 2**521 - 1

    _RINT = None

    def __init__(self):
        # self._PRIME = 2**19 - 1
        # self._PRIME = 2**127 - 1
        self._PRIME = 2**521 - 1
        self._RINT = functools.partial(random.SystemRandom().randint, 0)

    def _eval_at(self, poly, x, prime):
        """
        """
        accum = 0
        for coeff in reversed(poly):
            accum *= x
            accum += coeff
            accum %= prime
        return accum

    def make_random_shares(self, minimum, shares, secret):
        # secret(poly[0]) and shares(points)
        if minimum > shares:
            raise ValueError("Pool secret would be irrecoverable.")
        poly = [self._RINT(self._PRIME - 1) for i in range(minimum)]
        poly[0] = secret
        points = [(i, self._eval_at(poly, i, self._PRIME))
                  for i in range(1, shares + 1)]
        return poly[0], points

    def _extended_gcd(self, a, b):
        """
        Division in integers modulus p means finding the inverse of the
        denominator modulo p and then multiplying the numerator by this
        inverse (Note: inverse of A is B such that A*B % p == 1) this can
        be computed via extended Euclidean algorithm
        http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
        """
        x = 0
        last_x = 1
        y = 1
        last_y = 0
        while b != 0:
            quot = a // b
            a, b = b, a % b
            x, last_x = last_x - quot * x, x
            y, last_y = last_y - quot * y, y
        return last_x, last_y

    def _divmod(self, num, den, p):
        """Compute num / den modulo prime p

        To explain what this means, the return value will be such that
        the following is true: den * _divmod(num, den, p) % p == num
        """
        inv, _ = self._extended_gcd(den, p)
        return num * inv

    def _lagrange_interpolate(self, x, x_s, y_s, p):
        """
        Find the y-value for the given x, given n (x, y) points;
        k points will define a polynomial of up to kth order.
        """
        k = len(x_s)
        assert k == len(set(x_s)), "points must be distinct"

        def PI(vals):  # upper-case PI -- product of inputs
            accum = 1
            for v in vals:
                accum *= v
            return accum

        nums = []  # avoid inexact division
        dens = []
        for i in range(k):
            others = list(x_s)
            cur = others.pop(i)
            nums.append(PI(x - o for o in others))
            dens.append(PI(cur - o for o in others))
        den = PI(dens)
        num = sum([self._divmod(nums[i] * den * y_s[i] % p, dens[i], p)
                   for i in range(k)])
        return (self._divmod(num, den, p) + p) % p

    def recover_secret(self, shares: list):
        """recover secret
        """
        if len(shares) < 2:
            raise ValueError("need at least two shares")
        x_s, y_s = zip(*shares)
        return self._lagrange_interpolate(0, x_s, y_s, self._PRIME)

    def run(self, n, sec):
        """Main function"""
        secret, shares = self.make_random_shares(
            minimum=n, shares=n, secret=sec)

        # print('Secret:                                                     ',
        #       secret)
        # print('Shares:')
        # if shares:
        #     for share in shares:
        #         print('  ', share)

        # print('Secret recovered from shares:             ',
        #       self.recover_secret(shares))  #
        return shares
