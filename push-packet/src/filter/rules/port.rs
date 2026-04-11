use std::ops::{Range, RangeInclusive};

pub trait IntoPortRange {
    fn into_port_range(self) -> RangeInclusive<u16>;
}
impl IntoPortRange for u16 {
    fn into_port_range(self) -> RangeInclusive<u16> {
        self..=self
    }
}
impl IntoPortRange for RangeInclusive<u16> {
    fn into_port_range(self) -> RangeInclusive<u16> {
        self
    }
}
impl IntoPortRange for Range<u16> {
    fn into_port_range(self) -> RangeInclusive<u16> {
        self.start..=self.end - 1
    }
}

#[cfg(test)]
mod tests {
    use std::ops::RangeInclusive;

    use crate::filter::rules::port::IntoPortRange;

    fn converter(value: impl IntoPortRange) -> RangeInclusive<u16> {
        value.into_port_range()
    }

    #[test]
    fn single_port() {
        let test = converter(20);
        let control = 20..=20;
        assert_eq!(test, control)
    }

    #[test]
    fn test_range_inclusive() {
        let test = converter(0..=20);
        let control = 0..=20;
        assert_eq!(test, control);
    }

    #[test]
    fn test_range() {
        let test = converter(0..20);
        let control = 0..=19;
        assert_eq!(test, control)
    }
}
