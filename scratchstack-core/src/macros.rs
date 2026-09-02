//! Logging macros for records that may expose request material.
//!
//! Tracing an authentication or authorization decision means logging the material the decision
//! was made from: credentials, canonical requests, policy documents, the principal making the
//! request, the resources it names, and the session data (which carries request headers, tags,
//! and federation attributes). That is exactly what a log aggregator should never see, so the
//! macros here compile to nothing unless the `sensitive-logging` feature is enabled.
//!
//! Logs that carry no request material -- internal invariant violations, serializer failures --
//! use the [`log`] macros directly and are always compiled in.

/// Log a record that may expose request material, at an explicit [`log::Level`].
///
/// This expands to nothing unless the `sensitive-logging` feature is enabled: such records carry
/// credentials, canonical requests, policy documents, principals, resources, and session data,
/// none of which belong in an ordinary log stream. The format string and its arguments are still
/// type-checked when the feature is off, but nothing is evaluated at runtime.
#[cfg(feature = "sensitive-logging")]
#[macro_export]
macro_rules! sensitive_log {
    ($level:expr, $($arg:tt)+) => {
        $crate::__log::log!($level, $($arg)+)
    };
}

/// Log a record that may expose request material, at an explicit [`log::Level`].
///
/// This expands to nothing unless the `sensitive-logging` feature is enabled: such records carry
/// credentials, canonical requests, policy documents, principals, resources, and session data,
/// none of which belong in an ordinary log stream. The format string and its arguments are still
/// type-checked when the feature is off, but nothing is evaluated at runtime.
#[cfg(not(feature = "sensitive-logging"))]
#[macro_export]
macro_rules! sensitive_log {
    ($level:expr, $($arg:tt)+) => {{
        // Type-check the format string and its arguments so disabled call sites cannot rot,
        // without evaluating anything at runtime.
        if false {
            let _ = $level;
            let _ = ::std::format_args!($($arg)+);
        }
    }};
}

/// Log a `Trace` record that may expose request material.
///
/// This expands to nothing unless the `sensitive-logging` feature is enabled; see
/// [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_trace {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Trace, $($arg)+)
    };
}

/// Log a `Debug` record that may expose request material.
///
/// This expands to nothing unless the `sensitive-logging` feature is enabled; see
/// [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_debug {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Debug, $($arg)+)
    };
}

/// Log an `Info` record that may expose request material.
///
/// This expands to nothing unless the `sensitive-logging` feature is enabled; see
/// [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_info {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Info, $($arg)+)
    };
}

/// Log a `Warn` record that may expose request material.
///
/// This expands to nothing unless the `sensitive-logging` feature is enabled; see
/// [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_warn {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Warn, $($arg)+)
    };
}

/// Log an `Error` record that may expose request material.
///
/// This expands to nothing unless the `sensitive-logging` feature is enabled; see
/// [`sensitive_log`].
#[macro_export]
macro_rules! sensitive_error {
    ($($arg:tt)+) => {
        $crate::sensitive_log!($crate::__log::Level::Error, $($arg)+)
    };
}
