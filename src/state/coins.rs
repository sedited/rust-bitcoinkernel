//! Coin retrieval callback used by block validation.
//!
//! [`ChainstateManager::validate_block`](crate::ChainstateManager::validate_block)
//! validates a block against coins supplied by the caller rather than against a
//! full TXO set. It asks for those coins one at a time through a [`FetchCoinCallback`].
//!
//! # Difference from the notification callbacks
//!
//! Unlike the handlers registered on a [`Context`](crate::Context), this
//! callback is scoped to a single call. It is invoked synchronously, on the
//! thread that called `validate_block`, and is never retained afterwards, so it
//! needs neither `'static` nor `Send + Sync` and does not to be boxed.
//!

use std::{
    any::Any,
    cell::Cell,
    ffi::c_void,
    mem::ManuallyDrop,
    panic::{catch_unwind, AssertUnwindSafe},
};

use libbitcoinkernel_sys::{btck_Coin, btck_TransactionOutPoint};

use crate::{
    ffi::sealed::{AsPtr, FromPtr},
    Coin, TxOutPointRef,
};

/// Supplies the coins spent by a block being validated.
///
/// The callback is invoked for every output the block spends that was not also
/// created by the same block; outputs created and spent within the block are
/// resolved internally and never reach the callback.
///
/// Returning `None` reports the coin as unavailable, which fails validation with
/// a missing-inputs consensus error. There is no way to distinguish "absent from
/// my database" from "provably unspendable" - the kernel treats both alike.
///
/// # Implementations
///
/// Any `Fn(TxOutPointRef<'_>) -> Option<Coin>` implements this trait, so a
/// closure is usually all that is needed:
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, Coin, TxOutPointRef};
/// # fn example(lookup: impl Fn(TxOutPointRef<'_>) -> Option<Coin>) {
/// let fetch_coin = |out_point: TxOutPointRef<'_>| lookup(out_point);
/// # let _ = fetch_coin;
/// # }
/// ```
pub trait FetchCoinCallback {
    /// Returns the coin spent by `out_point`, or `None` if it is unavailable.
    fn fetch_coin(&self, out_point: TxOutPointRef<'_>) -> Option<Coin>;
}

impl<F> FetchCoinCallback for F
where
    F: Fn(TxOutPointRef<'_>) -> Option<Coin>,
{
    fn fetch_coin(&self, out_point: TxOutPointRef<'_>) -> Option<Coin> {
        self(out_point)
    }
}

/// Holds the caller's handler for the duration of a signle `validate_block`
/// call, along with a slot for a panic payload.
///
/// A panic must not unwind through `extern "C"` into the kernel, so the
/// trampoline catches it, reports the coin as unavailable, and stores the
/// payload here to be resumed once the kernel call has returned.
pub(crate) struct FetchCoinRegistry<'a> {
    handler: &'a dyn FetchCoinCallback,
    panic: Cell<Option<Box<dyn Any + Send>>>,
}

impl<'a> FetchCoinRegistry<'a> {
    pub(crate) fn new(handler: &'a dyn FetchCoinCallback) -> Self {
        Self {
            handler,
            panic: Cell::new(None),
        }
    }

    /// Returns the pointer to pass as the kernel's `user_data`.
    ///
    /// The kernel does not retain it past the call, so a borrow of a local is
    /// sufficient.
    pub(crate) fn as_user_data(&self) -> *mut c_void {
        self as *const FetchCoinRegistry<'a> as *mut c_void
    }

    /// Takes the panic payload captured during the call, if any.
    pub(crate) fn take_panic(&self) -> Option<Box<dyn Any + Send>> {
        self.panic.take()
    }
}

/// Trampoline invoked by the kernel for each coin the block spends.
///
/// # Safety
///
/// `user_data` must point to a live [`FetchCoinRegistry`], and `out_point` must
/// be valid for the duration of the call. Both hold for calls originating from
/// `validate_block`.
pub(crate) unsafe extern "C" fn validation_fetch_coin_wrapper(
    user_data: *mut c_void,
    out_point: *const btck_TransactionOutPoint,
) -> *mut btck_Coin {
    let registry = &*(user_data as *const FetchCoinRegistry<'_>);

    let fetched = catch_unwind(AssertUnwindSafe(|| {
        registry
            .handler
            .fetch_coin(TxOutPointRef::from_ptr(out_point))
    }));

    match fetched {
        Ok(Some(coin)) => ManuallyDrop::new(coin).as_ptr() as *mut btck_Coin,
        Ok(None) => std::ptr::null_mut(),
        Err(payload) => {
            registry.panic.set(Some(payload));
            std::ptr::null_mut()
        }
    }
}
