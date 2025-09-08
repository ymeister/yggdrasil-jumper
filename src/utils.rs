use std::{
    fmt::Display,
    future::Future,
    net::{Ipv6Addr, SocketAddrV6},
    str::FromStr,
};
use tracing::warn;

use crate::{map_warn, SilentResult};

mod cancellation;
mod defer;
mod macros;
mod sockets;
mod timeout;

pub use cancellation::*;
pub use defer::*;
pub use sockets::*;
pub use timeout::*;

/// Yggdrasil IPv6 address appears a lot in the logs, so it should be short
pub fn pretty_ip(ip: Ipv6Addr) -> String {
    let [f1, f2, .., l1, l2] = ip.segments();
    format!("[{f1:x}:{f2:x}:…:{l1:x}:{l2:x}]")
}

pub fn pretty_addr(addr: SocketAddrV6) -> String {
    format!("{}:{}", pretty_ip(*addr.ip()), addr.port())
}

/// Attach data to the body of the function (executing it's [`Drop::drop()`])
pub trait FutureAttach: Future {
    fn attach<D>(self, drop: D) -> impl Future<Output = Self::Output>;
}

impl<F: Future> FutureAttach for F {
    fn attach<D>(self, drop: D) -> impl Future<Output = Self::Output> {
        let fut = self;
        async move {
            let _drop = drop;
            fut.await
        }
    }
}

pub struct CsvIter<T>(pub T);

impl<I, S> CsvIter<I>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    pub fn parse<V, E>(&mut self, desc: impl AsRef<str>) -> SilentResult<V>
    where
        V: FromStr<Err = E>,
        E: Display,
    {
        let desc = desc.as_ref();
        let Some(val) = self.0.next() else {
            warn!("Missing {desc}");
            return Err(());
        };
        let val = val.as_ref();
        V::from_str(val).map_err(map_warn!("Can't parse {desc}: {val:?}"))
    }

    pub fn skip(&mut self, desc: impl AsRef<str>) {
        let _ = desc.as_ref();
        self.0.next();
    }
}
