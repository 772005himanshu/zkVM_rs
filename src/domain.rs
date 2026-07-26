/// Evaluation domains for STARK polynomials.
///
/// In a STARK, we work with two domains:
/// 1. **Trace domain**: a multiplicative subgroup H = {omega^0, omega^1, ..., omega^{n-1}}
///    where omega is a root of unity of order n. The trace polynomial P satisfies
///    P(omega^i) = trace[i].
///
/// 2. **LDE domain**: a *coset* of a larger subgroup, used for low-degree extension.
///    If we use blowup factor 8, the LDE domain has 8n points. We use a coset
///    (shift * g^i) so the LDE domain doesn't overlap with the trace domain —
///    this avoids division by zero when computing the quotient Q(x) = C(x) / Z_H(x).
use crate::field::Fp;

/// A multiplicative domain: the set {offset * g^0, offset * g^1, ..., offset * g^{size-1}}.
#[derive(Debug, Clone)]
pub struct Domain {
    /// generator of the subgroup (a root of unity of the given order).
    pub generator: Fp,
    /// Number of elements.
    pub size: usize,
    /// Coset offset. For the trace domain this is 1; for the LDE domain it's a shift.
    pub offset: Fp,
}

impl Domain {
    /// Create the trace domain: a subgroup of the given size.
    pub fn trace_domain(size: usize) -> Self {
        assert!(size.is_power_of_two());
        let generator = Fp::root_of_unity(size as u64);
        Domain {
            generator,
            size,
            offset: Fp::ONE,
        }
    }

    /// Create the LDE domain: a coset of a larger subgroup.
    /// The LDE size is `trace_size * blowup_factor`.
    /// The coset offset ensures no overlap with the trace domain.
    pub fn lde_domain(trace_size: usize, blowup_factor: usize) -> Self {
        let lde_size = trace_size * blowup_factor;
        assert!(lde_size.is_power_of_two());
        let generator = Fp::root_of_unity(lde_size as u64);

        // Use a primitive root as the coset offset.
        // This shifts the domain away from the trace domain.
        // We use Fp(7)^{(p-1)/(2*lde_size)} as the offset — an element that is NOT
        // in either the trace or LDE subgroup.
        let offset = Fp::new(7).pow((crate::field::P - 1) / (2 * lde_size as u64));

        Domain {
            generator,
            size: lde_size,
            offset,
        }
    }

    /// Return all elements of this domain.
    pub fn elements(&self) -> Vec<Fp> {
        let mut elems = Vec::with_capacity(self.size);
        let mut current = self.offset;
        for _ in 0..self.size {
            elems.push(current);
            current = current * self.generator;
        }
        elems
    }

    /// Get the i-th element: offset * g^i.
    pub fn element(&self, i: usize) -> Fp {
        self.offset * self.generator.pow(i as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_domain() {
        let d = Domain::trace_domain(8);
        let elems = d.elements();
        assert_eq!(elems.len(), 8);
        // First element should be 1 (offset=1, g^0=1)
        assert_eq!(elems[0], Fp::ONE);
        // g^8 should be 1 (full cycle)
        assert_eq!(d.generator.pow(8), Fp::ONE);
    }

    #[test]
    fn test_lde_domain_no_overlap() {
        let trace_d = Domain::trace_domain(8);
        let lde_d = Domain::lde_domain(8, 8);

        let trace_elems: std::collections::HashSet<_> =
            trace_d.elements().into_iter().collect();
        let lde_elems: std::collections::HashSet<_> =
            lde_d.elements().into_iter().collect();

        // LDE domain (coset) should not overlap with trace domain
        let overlap: Vec<_> = trace_elems.intersection(&lde_elems).collect();
        assert!(overlap.is_empty(), "LDE domain overlaps with trace domain");
    }

    #[test]
    fn test_domain_elements_count() {
        let d = Domain::lde_domain(8, 8);
        assert_eq!(d.elements().len(), 64);
    }
}