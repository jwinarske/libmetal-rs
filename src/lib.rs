#![no_std]
#![feature(const_fn)]

#[cfg(test)]
#[macro_use]
extern crate std;

extern crate alloc;

pub mod state;
pub mod io_region;
