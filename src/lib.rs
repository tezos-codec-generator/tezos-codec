extern crate tedium;
#[cfg(any(feature = "lima", feature = "mumbai"))]
extern crate tezos_codegen;
#[macro_use]
extern crate serde;

pub use tedium::*;

pub mod core;
pub mod util;

pub mod traits;

pub mod babylon;
pub mod carthage;
pub mod delphi;
pub mod edo;
pub mod florence;
pub mod granada;
pub mod hangzhou;
pub mod ithaca;
pub mod jakarta;
pub mod kathmandu;
#[cfg(feature = "lima")]
pub mod lima;

#[cfg(feature = "mumbai")]
pub mod mumbai;

pub mod alpha;
