/// Goldilocks field: F_p where p = 2^64 - 2^32 + 1
///
/// This prime is special because:
/// - It fits in a u64 (just barely)
/// - Multiplication uses u128, then efficient reduction
/// - The multiplicative group has order p-1 = 2^32 * (2^32 - 1),
///   so it contains a subgroup of order 2^32 — perfect for FRI domains
/// - It's the same field used by Plonky2 in production
use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// The Goldilocks prime: 2^64 - 2^32 + 1
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// A generator of the full multiplicative group of order p-1.
/// 7 is a primitive root mod p.
const MULTIPLICATIVE_GENERATOR: u64 = 7;

/// A field element in the Goldilocks field.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fp(u64);

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    /// Create a field element from a u64. Reduces mod p.
    pub fn new(val: u64) -> Self {
        // If val >= P, reduce. Since P is close to 2^64, val < 2*P always holds for u64.
        if val >= P {
            Fp(val - P)
        } else {
            Fp(val)
        }
    }

    /// Create a field element from a larger value (used internally).
    fn from_u128(val: u128) -> Self {
        // Goldilocks reduction:
        // val = val_hi * 2^64 + val_lo
        // Since 2^64 ≡ 2^32 - 1 (mod p), we have:
        // val ≡ val_lo + val_hi * (2^32 - 1) (mod p)
        let val_lo = val as u64;
        let val_hi = (val >> 64) as u64;

        // val_hi * (2^32 - 1) = val_hi * 2^32 - val_hi
        let hi_shifted = (val_hi as u128) << 32;
        let reduced = (val_lo as u128) + hi_shifted - (val_hi as u128);

        // The result might still be >= p or might have underflowed.
        // Do a final mod-p reduction.
        let r = reduced % (P as u128);
        Fp(r as u64)
    }

    /// Get the raw u64 value (already reduced mod p).
    pub fn value(self) -> u64 {
        self.0
    }

    /// Compute self^exp using binary exponentiation.
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Fp::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        result
    }

    /// Multiplicative inverse via Fermat's little theorem: a^{-1} = a^{p-2} mod p.
    /// Panics if self is zero.
    pub fn inv(self) -> Self {
        assert!(self.0 != 0, "cannot invert zero");
        self.pow(P - 2)
    }

    /// Returns a primitive root of unity of the given order.
    /// `order` must be a power of 2 and must divide 2^32.
    ///
    /// The multiplicative group has order p-1 = 2^32 * (2^32 - 1).
    /// A generator g of the full group raised to (p-1)/order gives
    /// an element of exactly that order.
    pub fn root_of_unity(order: u64) -> Self {
        assert!(order.is_power_of_two(), "order must be a power of 2");
        assert!(order <= (1u64 << 32), "order must divide 2^32");

        // g^{(p-1)/order} has order `order`
        let g = Fp::new(MULTIPLICATIVE_GENERATOR);
        let exp = (P - 1) / order;
        g.pow(exp)
    }
}

// --- Arithmetic operator implementations ---

impl Add for Fp {
    type Output = Fp;
    fn add(self, rhs: Fp) -> Fp {
        let sum = (self.0 as u128) + (rhs.0 as u128);
        let r = if sum >= (P as u128) {
            (sum - (P as u128)) as u64
        } else {
            sum as u64
        };
        Fp(r)
    }
}

impl Sub for Fp {
    type Output = Fp;
    fn sub(self, rhs: Fp) -> Fp {
        if self.0 >= rhs.0 {
            Fp(self.0 - rhs.0)
        } else {
            // self.0 - rhs.0 + P (borrow from p)
            Fp(P - rhs.0 + self.0)
        }
    }
}

impl Mul for Fp {
    type Output = Fp;
    fn mul(self, rhs: Fp) -> Fp {
        let product = (self.0 as u128) * (rhs.0 as u128);
        Fp::from_u128(product)
    }
}

impl Div for Fp {
    type Output = Fp;
    fn div(self, rhs: Fp) -> Fp {
        self * rhs.inv()
    }
}

impl Neg for Fp {
    type Output = Fp;
    fn neg(self) -> Fp {
        if self.0 == 0 {
            Fp::ZERO
        } else {
            Fp(P - self.0)
        }
    }
}

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp({})", self.0)
    }
}

impl fmt::Display for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Fp {
    fn from(val: u64) -> Self {
        Fp::new(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = Fp::new(10);
        let b = Fp::new(20);
        assert_eq!((a + b).value(), 30);
        assert_eq!((b - a).value(), 10);
        assert_eq!((a * b).value(), 200);
    }

    #[test]
    fn test_subtraction_underflow() {
        let a = Fp::new(5);
        let b = Fp::new(10);
        let result = a - b;
        // 5 - 10 mod p = p - 5
        assert_eq!(result.value(), P - 5);
        // Adding 10 back should give 5
        assert_eq!((result + b).value(), 5);
    }

    #[test]
    fn test_negation() {
        let a = Fp::new(42);
        let neg_a = -a;
        assert_eq!((a + neg_a).value(), 0);
        assert_eq!((-Fp::ZERO).value(), 0);
    }

    #[test]
    fn test_multiplication_large() {
        // Test near-overflow values
        let a = Fp::new(P - 1);
        let b = Fp::new(P - 1);
        let result = a * b;
        // (P-1)^2 mod P = 1 (since P-1 ≡ -1, and (-1)^2 = 1)
        assert_eq!(result.value(), 1);
    }

    #[test]
    fn test_inverse() {
        let a = Fp::new(42);
        let a_inv = a.inv();
        assert_eq!((a * a_inv).value(), 1);
    }

    #[test]
    fn test_inverse_various() {
        for val in [1, 2, 3, 7, 100, 12345, P - 1] {
            let a = Fp::new(val);
            let a_inv = a.inv();
            assert_eq!((a * a_inv).value(), 1, "failed for {}", val);
        }
    }

    #[test]
    fn test_division() {
        let a = Fp::new(100);
        let b = Fp::new(10);
        let result = a / b;
        assert_eq!((result * b).value(), 100);
    }

    #[test]
    fn test_pow() {
        let a = Fp::new(3);
        assert_eq!(a.pow(0).value(), 1);
        assert_eq!(a.pow(1).value(), 3);
        assert_eq!(a.pow(2).value(), 9);
        assert_eq!(a.pow(3).value(), 27);
        assert_eq!(a.pow(10).value(), 59049);
    }

    #[test]
    fn test_root_of_unity() {
        // Root of unity of order n should satisfy: omega^n = 1
        for log_n in 1..=10 {
            let n = 1u64 << log_n;
            let omega = Fp::root_of_unity(n);
            assert_eq!(omega.pow(n).value(), 1, "omega^{} != 1", n);
            // And omega^{n/2} should NOT be 1 (primitive root)
            if n > 1 {
                assert_ne!(omega.pow(n / 2).value(), 1, "omega is not primitive for order {}", n);
            }
        }
    }

    #[test]
    fn test_new_reduces() {
        let a = Fp::new(P);
        assert_eq!(a.value(), 0);
        let b = Fp::new(P + 1);
        assert_eq!(b.value(), 1);
    }

    #[test]
    fn test_field_identities() {
        let a = Fp::new(12345);
        // Additive identity
        assert_eq!((a + Fp::ZERO).value(), a.value());
        // Multiplicative identity
        assert_eq!((a * Fp::ONE).value(), a.value());
        // Self - self = 0
        assert_eq!((a - a).value(), 0);
        // a * a^{-1} = 1
        assert_eq!((a * a.inv()).value(), 1);
    }
}
