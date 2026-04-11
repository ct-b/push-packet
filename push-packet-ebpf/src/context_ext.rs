use core::mem;

use aya_ebpf::programs::XdpContext;

pub struct Boundaries {
    start: usize,
    end: usize,
}

impl Boundaries {
    #[inline(always)]
    pub fn ptr_at<T>(&self, offset: usize) -> Result<*const T, ()> {
        let len = mem::size_of::<T>();
        if self.start + offset + len > self.end {
            return Err(());
        }
        Ok((self.start + offset) as *const T)
    }
}

pub trait ContextExt {
    fn boundaries(&self) -> Boundaries;
}

impl ContextExt for XdpContext {
    fn boundaries(&self) -> Boundaries {
        Boundaries {
            start: self.data(),
            end: self.data_end(),
        }
    }
}
