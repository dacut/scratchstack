//! Logging macros for records that may expose request material.
//!
//! Tracing an authentication or authorization decision means logging the material the decision
//! was made from: credentials, canonical requests, policy documents, the principal making the
//! request, the resources it names, and the session data (which carries request headers, tags,
//! and federation attributes). That is exactly what a log aggregator should never see, so the
//! macros here compile to nothing unless the **calling crate's** `sensitive-logging` feature is
//! enabled.
//!
//! The gate is deliberately not a feature of this crate. Cargo unifies features across the
//! dependency graph, so a gate here would mean that enabling sensitive logging for one crate
//! switched on every other crate's records too. Instead the check is `cfg!(feature =
//! "sensitive-logging")` inside the macro body, which is evaluated where the macro expands --
//! so each crate that uses these macros declares its own `sensitive-logging` feature, and
//! enabling it exposes that crate's records and no other's.
//!
//! Logs that carry no request material -- internal invariant violations, serializer failures --
//! use the [`log`] macros directly and are always compiled in.

/// Log a record that may expose request material, at an explicit [`log::Level`].
///
/// This expands to nothing unless the `sensitive-logging` feature of the crate it is invoked
/// from is enabled (see the [`macros`][crate::macros] module): such records carry credentials,
/// canonical requests, policy documents, principals, resources, and session data, none of which
/// belong in an ordinary log stream. The format string and its arguments are still type-checked
/// when the feature is off, but nothing is evaluated at runtime.
#[macro_export]
macro_rules! sensitive_log {
    ($level:expr, $($arg:tt)+) => {{
        // `cfg!` is resolved in the crate this expands in, so this checks the calling crate's
        // feature. When it is off, the branch is dead code: type-checked, never evaluated.
        if ::core::cfg!(feature = "sensitive-logging") {
            $crate::__log::log!($level, $($arg)+);
        }
    }};
}

/// Log a `Trace` record that may expose request material.
///
/// This expands to nothing unless the calling crate's `sensitive-logging` feature is enabled;
/// see [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_trace {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Trace, $($arg)+)
    };
}

/// Log a `Debug` record that may expose request material.
///
/// This expands to nothing unless the calling crate's `sensitive-logging` feature is enabled;
/// see [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_debug {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Debug, $($arg)+)
    };
}

/// Log an `Info` record that may expose request material.
///
/// This expands to nothing unless the calling crate's `sensitive-logging` feature is enabled;
/// see [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_info {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Info, $($arg)+)
    };
}

/// Log a `Warn` record that may expose request material.
///
/// This expands to nothing unless the calling crate's `sensitive-logging` feature is enabled;
/// see [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_warn {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Warn, $($arg)+)
    };
}

/// Log an `Error` record that may expose request material.
///
/// This expands to nothing unless the calling crate's `sensitive-logging` feature is enabled;
/// see [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_error {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Error, $($arg)+)
    };
}
