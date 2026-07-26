/// Polynomial arithmetic over the Goldilocks field.
///
/// We use a simple coefficient representation: coeffs[i] is the coefficient of x^i.
/// All operations are naive O(n^2) — this is intentional for clarity.
/// Production systems use NTT (Number Theoretic Transform) for O(n log n).
use crate::field::Fp;

/// A polynomial represented by its coefficients: coeffs[i] * x^i.
#[derive(Debug, Clone)]
pub struct Polynomial {
    pub coeffs: Vec<Fp>,
}

impl Polynomial {
    /// Zero polynomial.
    pub fn zero() -> Self {
        Polynomial { coeffs: vec![] }
    }

    /// Constant polynomial.
    pub fn constant(c: Fp) -> Self {
        if c == Fp::ZERO {
            Self::zero()
        } else {
            Polynomial { coeffs: vec![c] }
        }
    }

    /// Degree of the polynomial (-1 for zero polynomial, represented as 0 here).
    pub fn degree(&self) -> usize {
        if self.coeffs.is_empty() {
            return 0;
        }
        // Find last non-zero coefficient
        for i in (0..self.coeffs.len()).rev() {
            if self.coeffs[i] != Fp::ZERO {
                return i;
            }
        }
        0
    }

    /// Evaluate the polynomial at a point using Horner's method.
    /// P(x) = c_0 + c_1*x + c_2*x^2 + ... = c_0 + x*(c_1 + x*(c_2 + ...))
    pub fn evaluate(&self, x: Fp) -> Fp {
        if self.coeffs.is_empty() {
            return Fp::ZERO;
        }
        let mut result = Fp::ZERO;
        for coeff in self.coeffs.iter().rev() {
            result = result * x + *coeff;
        }
        result
    }

    /// Evaluate the polynomial at all points in a domain.
    pub fn evaluate_domain(&self, domain: &[Fp]) -> Vec<Fp> {
        domain.iter().map(|&x| self.evaluate(x)).collect()
    }

    /// Lagrange interpolation: given points (x_i, y_i), find the unique polynomial
    /// of degree < n that passes through all of them.
    ///
    /// This is the mathematical heart of arithmetization: we turn a column of trace
    /// values into a polynomial that "encodes" those values.
    pub fn interpolate(xs: &[Fp], ys: &[Fp]) -> Self {
        assert_eq!(xs.len(), ys.len());
        let n = xs.len();
        if n == 0 {
            return Self::zero();
        }

        // result = SUM_i y_i * L_i(x)
        // where L_i(x) = PROD_{j != i} (x - x_j) / (x_i - x_j)
        let mut result = vec![Fp::ZERO; n];

        for i in 0..n {
            // Compute the Lagrange basis polynomial L_i(x)
            // L_i(x) = PROD_{j != i} (x - x_j) / (x_i - x_j)

            // First compute the denominator (a constant)
            let mut denom = Fp::ONE;
            for j in 0..n {
                if j != i {
                    denom = denom * (xs[i] - xs[j]);
                }
            }
            let denom_inv = denom.inv();

            // Now build the numerator polynomial PROD_{j != i} (x - x_j)
            // We do this by multiplying linear factors one at a time.
            let mut basis = vec![Fp::ZERO; n];
            basis[0] = Fp::ONE; // start with constant 1

            let mut deg = 0;
            for j in 0..n {
                if j == i {
                    continue;
                }
                // Multiply current basis by (x - x_j):
                // new[k] = old[k-1] - x_j * old[k]
                let neg_xj = -xs[j];
                for k in (1..=deg + 1).rev() {
                    basis[k] = basis[k - 1] + neg_xj * basis[k];
                }
                basis[0] = neg_xj * basis[0];
                deg += 1;
            }

            // Scale by y_i / denom and accumulate
            let scale = ys[i] * denom_inv;
            for k in 0..n {
                result[k] = result[k] + scale * basis[k];
            }
        }

        // Trim trailing zeros
        while result.len() > 1 && result.last() == Some(&Fp::ZERO) {
            result.pop();
        }

        Polynomial { coeffs: result }
    }

    /// Interpolate values defined on a multiplicative subgroup.
    /// xs = [omega^0, omega^1, ..., omega^{n-1}] where omega is a root of unity of order n.
    pub fn interpolate_subgroup(omega: Fp, ys: &[Fp]) -> Self {
        let n = ys.len();
        let xs: Vec<Fp> = (0..n).map(|i| omega.pow(i as u64)).collect();
        Self::interpolate(&xs, ys)
    }

    /// Polynomial addition.
    pub fn add(&self, other: &Polynomial) -> Polynomial {
        let len = self.coeffs.len().max(other.coeffs.len());
        let mut result = vec![Fp::ZERO; len];
        for (i, c) in self.coeffs.iter().enumerate() {
            result[i] = result[i] + *c;
        }
        for (i, c) in other.coeffs.iter().enumerate() {
            result[i] = result[i] + *c;
        }
        Polynomial { coeffs: result }
    }

    /// Polynomial subtraction.
    pub fn sub(&self, other: &Polynomial) -> Polynomial {
        let len = self.coeffs.len().max(other.coeffs.len());
        let mut result = vec![Fp::ZERO; len];
        for (i, c) in self.coeffs.iter().enumerate() {
            result[i] = result[i] + *c;
        }
        for (i, c) in other.coeffs.iter().enumerate() {
            result[i] = result[i] - *c;
        }
        Polynomial { coeffs: result }
    }

    /// Polynomial multiplication (naive O(n*m)).
    pub fn mul(&self, other: &Polynomial) -> Polynomial {
        if self.coeffs.is_empty() || other.coeffs.is_empty() {
            return Self::zero();
        }
        let len = self.coeffs.len() + other.coeffs.len() - 1;
        let mut result = vec![Fp::ZERO; len];
        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in other.coeffs.iter().enumerate() {
                result[i + j] = result[i + j] + *a * *b;
            }
        }
        Polynomial { coeffs: result }
    }

    /// Scalar multiplication.
    pub fn scale(&self, s: Fp) -> Polynomial {
        Polynomial {
            coeffs: self.coeffs.iter().map(|c| *c * s).collect(),
        }
    }

    /// Polynomial division with remainder: self = quotient * divisor + remainder.
    /// Returns (quotient, remainder).
    pub fn div_rem(&self, divisor: &Polynomial) -> (Polynomial, Polynomial) {
        let d_deg = divisor.degree();
        let n_deg = self.degree();
        if self.coeffs.is_empty() || n_deg < d_deg {
            return (Self::zero(), self.clone());
        }

        let mut remainder = self.coeffs.clone();
        let lead_inv = divisor.coeffs[d_deg].inv();

        let q_len = n_deg - d_deg + 1;
        let mut quotient = vec![Fp::ZERO; q_len];

        for i in (0..q_len).rev() {
            let coeff = remainder[i + d_deg] * lead_inv;
            quotient[i] = coeff;
            for j in 0..=d_deg {
                remainder[i + j] = remainder[i + j] - coeff * divisor.coeffs[j];
            }
        }

        // Trim remainder
        while remainder.len() > 1 && remainder.last() == Some(&Fp::ZERO) {
            remainder.pop();
        }

        (Polynomial { coeffs: quotient }, Polynomial { coeffs: remainder })
    }

    /// Exact division: self / divisor. Panics if there is a remainder.
    pub fn div_exact(&self, divisor: &Polynomial) -> Polynomial {
        let (q, r) = self.div_rem(divisor);
        assert!(
            r.coeffs.is_empty() || r.coeffs.iter().all(|c| *c == Fp::ZERO),
            "division has non-zero remainder"
        );
        q
    }

    /// The vanishing polynomial for a multiplicative subgroup of order n:
    /// Z_H(x) = x^n - 1
    ///
    /// This polynomial is zero at exactly the points {omega^0, omega^1, ..., omega^{n-1}}.
    /// If constraint polynomial C(x) is also zero at all those points, then
    /// C(x) is divisible by Z_H(x) — this is the key fact that makes STARK proofs work.
    pub fn vanishing(n: usize) -> Self {
        // x^n - 1: coefficient of x^0 is -1, coefficient of x^n is 1
        let mut coeffs = vec![Fp::ZERO; n + 1];
        coeffs[0] = -Fp::ONE; // constant term = -1
        coeffs[n] = Fp::ONE;  // leading term = x^n
        Polynomial { coeffs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate() {
        // P(x) = 3 + 2x + x^2
        let p = Polynomial {
            coeffs: vec![Fp::new(3), Fp::new(2), Fp::new(1)],
        };
        // P(0) = 3
        assert_eq!(p.evaluate(Fp::ZERO).value(), 3);
        // P(1) = 3+2+1 = 6
        assert_eq!(p.evaluate(Fp::ONE).value(), 6);
        // P(2) = 3+4+4 = 11
        assert_eq!(p.evaluate(Fp::new(2)).value(), 11);
    }

    #[test]
    fn test_interpolation() {
        // Interpolate through (0,5), (1,10), (2,15)
        let xs = vec![Fp::new(0), Fp::new(1), Fp::new(2)];
        let ys = vec![Fp::new(5), Fp::new(10), Fp::new(15)];
        let p = Polynomial::interpolate(&xs, &ys);

        for (x, y) in xs.iter().zip(ys.iter()) {
            assert_eq!(p.evaluate(*x), *y);
        }
    }

    #[test]
    fn test_interpolation_subgroup() {
        // Use a subgroup of order 4
        let omega = Fp::root_of_unity(4);
        let ys = vec![Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)];
        let p = Polynomial::interpolate_subgroup(omega, &ys);

        for (i, y) in ys.iter().enumerate() {
            let x = omega.pow(i as u64);
            assert_eq!(p.evaluate(x), *y);
        }
    }

    #[test]
    fn test_multiplication() {
        // (1 + x) * (1 + x) = 1 + 2x + x^2
        let a = Polynomial { coeffs: vec![Fp::ONE, Fp::ONE] };
        let b = a.mul(&a);
        assert_eq!(b.evaluate(Fp::new(0)).value(), 1);
        assert_eq!(b.evaluate(Fp::new(1)).value(), 4);
        assert_eq!(b.evaluate(Fp::new(2)).value(), 9);
    }

    #[test]
    fn test_division() {
        // (x^2 - 1) / (x - 1) = (x + 1)
        let num = Polynomial { coeffs: vec![-Fp::ONE, Fp::ZERO, Fp::ONE] }; // -1 + x^2
        let den = Polynomial { coeffs: vec![-Fp::ONE, Fp::ONE] }; // -1 + x
        let q = num.div_exact(&den);
        // q should be (1 + x)
        assert_eq!(q.evaluate(Fp::new(0)).value(), 1);
        assert_eq!(q.evaluate(Fp::new(1)).value(), 2);
    }

    #[test]
    fn test_vanishing() {
        let n = 4;
        let omega = Fp::root_of_unity(n as u64);
        let z = Polynomial::vanishing(n);

        // Z_H(omega^i) should be zero for all i in {0..n-1}
        for i in 0..n {
            let x = omega.pow(i as u64);
            assert_eq!(z.evaluate(x), Fp::ZERO, "Z_H(omega^{}) != 0", i);
        }

        // Z_H at a random point should NOT be zero
        assert_ne!(z.evaluate(Fp::new(42)), Fp::ZERO);
    }
}