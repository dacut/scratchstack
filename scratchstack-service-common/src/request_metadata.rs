//! Facts about an individual request beyond the request parameters themselves.

use {
    bon::Builder,
    scratchstack_config::ResolvedForwardedForConfig,
    scratchstack_core::axum::{
        extract::{ConnectInfo, Extension},
        http::HeaderMap,
    },
    std::net::{IpAddr, SocketAddr},
};

/// What the connection a request arrived on says about the request.
///
/// These describe the request itself rather than the caller or the resources it names, and back
/// the corresponding condition keys during policy evaluation. They travel together from the
/// request dispatcher to the authorization check, so a service's operations need not know which
/// condition keys are derived from them.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`RequestMetadata::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_service_common::RequestMetadata;
/// # use std::net::{IpAddr, Ipv4Addr};
/// let _ = RequestMetadata {
///     secure_transport: true,
///     source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
/// };
/// ```
#[derive(Builder, Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestMetadata {
    /// Whether the request arrived over TLS; supplies the `aws:SecureTransport` condition key.
    pub secure_transport: bool,

    /// The address the request came from; supplies the `aws:SourceIp` condition key. This is the
    /// address of the client a trusted proxy forwarded the request for, when the listener is
    /// configured to believe one, and otherwise the address the connection itself came from.
    pub source_ip: IpAddr,
}

impl RequestMetadata {
    /// Derive the metadata for a request from the connection it arrived on: whether the listener
    /// terminates TLS and which proxies it believes (both carried by
    /// [`ServiceState`][crate::ServiceState], since the configuration decides them), plus the
    /// connection information and headers the request itself carries.
    ///
    /// Returns `None` when the request carries no connection information, which happens only if
    /// the service is served without [`serve`][crate::serve]. Callers must fail such a request
    /// closed rather than evaluate policies without `aws:SourceIp`: an absent value silently
    /// satisfies a `NotIpAddress` condition, so an explicit deny outside a CIDR block would not
    /// fire.
    pub fn from_connection(
        secure_transport: bool,
        forwarded_for: Option<&ResolvedForwardedForConfig>,
        connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
        headers: &HeaderMap,
    ) -> Option<Self> {
        let Extension(ConnectInfo(peer)) = connect_info?;

        Some(
            Self::builder()
                .secure_transport(secure_transport)
                .source_ip(source_ip(peer, forwarded_for, headers))
                .build(),
        )
    }
}

/// The address a request came from, as `aws:SourceIp` reports it.
///
/// This is the peer address unless the listener is configured to believe a forwarded header and
/// the request arrived from one of the proxies it names.
fn source_ip(peer: SocketAddr, forwarded_for: Option<&ResolvedForwardedForConfig>, headers: &HeaderMap) -> IpAddr {
    let peer = unmap_ipv4(peer.ip());

    // The header is only as trustworthy as the hop that appended to it: a client connecting
    // directly can send whatever it likes, so the header is read only for requests that arrived
    // from a proxy the configuration names.
    let Some(forwarded_for) = forwarded_for.filter(|forwarded_for| forwarded_for.trusts(peer)) else {
        return peer;
    };

    let mut entries = Vec::new();
    for value in headers.get_all(&forwarded_for.header) {
        let Ok(value) = value.to_str() else {
            // A header that is not text at all says nothing about who sent the request.
            log::debug!("Ignoring non-ASCII {} header from {peer}", forwarded_for.header);
            return peer;
        };
        entries.extend(value.split(',').map(str::trim).filter(|entry| !entry.is_empty()));
    }

    // Each hop appends the address it accepted the request from, so the list reads
    // `client, proxy-1, ..., proxy-n` and only the entries the trusted proxies contributed can
    // be believed. Walking right to left, the first address that is not itself a trusted proxy
    // is the client; anything further left was supplied by that client and is ignored. If every
    // entry is trusted, the leftmost one is the closest thing to a client the chain reports.
    let mut client = peer;
    for entry in entries.iter().rev() {
        let Some(addr) = parse_forwarded(entry) else {
            // The chain cannot be followed past an entry that names no address, so attribute
            // the request to the last hop that did.
            log::debug!("Ignoring unparseable {} entry {entry:?} from {peer}", forwarded_for.header);
            break;
        };

        if !forwarded_for.trusts(addr) {
            return addr;
        }

        client = addr;
    }

    client
}

/// Parse one entry of a forwarded header, which names an address and may append a port.
fn parse_forwarded(entry: &str) -> Option<IpAddr> {
    if let Ok(addr) = entry.parse::<IpAddr>() {
        return Some(unmap_ipv4(addr));
    }

    // Proxies vary: some append the client's port as `192.0.2.1:443` or `[2001:db8::1]:443`,
    // and some bracket an IPv6 address whether or not a port follows.
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Some(unmap_ipv4(addr.ip()));
    }

    let bracketed = entry.strip_prefix('[')?.strip_suffix(']')?;
    bracketed.parse::<IpAddr>().ok().map(unmap_ipv4)
}

/// Unwrap an IPv4-mapped IPv6 address, such as a dual-stack listener reports for an IPv4 peer.
///
/// Policies are written against the address family the client actually used, so the mapping is
/// undone before the address reaches policy evaluation.
fn unmap_ipv4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        addr => addr,
    }
}

#[cfg(test)]
mod tests {
    use {
        super::RequestMetadata,
        pretty_assertions::assert_eq,
        scratchstack_config::{ForwardedForConfig, Resolvable as _, ResolvedForwardedForConfig},
        scratchstack_core::axum::{
            extract::{ConnectInfo, Extension},
            http::HeaderMap,
        },
        std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    };

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    const PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const INNER_PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    /// Build the connection information a handler receives for a peer at `ip`.
    fn connect_info(ip: IpAddr) -> Option<Extension<ConnectInfo<SocketAddr>>> {
        Some(Extension(ConnectInfo(SocketAddr::new(ip, 49152))))
    }

    /// A listener that believes proxies in `10.0.0.0/8`, reading the default header.
    fn forwarded_for() -> ResolvedForwardedForConfig {
        ForwardedForConfig::builder()
            .trusted_proxies(vec!["10.0.0.0/8".to_string()])
            .build()
            .resolve()
            .expect("failed to resolve forwarded_for configuration")
    }

    /// Build a header map carrying `values` as separate `X-Forwarded-For` header lines.
    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", value.parse().expect("invalid header value"));
        }
        headers
    }

    /// The source IP `from_connection` derives for a peer, with no forwarding configured.
    fn source_ip_of(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        RequestMetadata::from_connection(true, None, connect_info(peer), headers).expect("no metadata").source_ip
    }

    /// The source IP `from_connection` derives for a peer, believing proxies in `10.0.0.0/8`.
    fn forwarded_source_ip_of(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        RequestMetadata::from_connection(true, Some(&forwarded_for()), connect_info(peer), headers)
            .expect("no metadata")
            .source_ip
    }

    #[test]
    fn source_ip_is_the_peer_address() {
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        assert_eq!(source_ip_of(v4, &HeaderMap::new()), v4);

        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(source_ip_of(v6, &HeaderMap::new()), v6);
    }

    /// A dual-stack listener reports an IPv4 peer as an IPv4-mapped IPv6 address; policies are
    /// written against the family the client used, so the mapping is unwrapped.
    #[test]
    fn ipv4_mapped_peers_are_reported_as_ipv4() {
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 10).to_ipv6_mapped());

        assert_eq!(source_ip_of(mapped, &HeaderMap::new()), CLIENT);
    }

    /// The listener's TLS configuration, not anything the caller sends, decides
    /// `aws:SecureTransport`.
    #[test]
    fn secure_transport_is_carried_through() {
        let peer = connect_info(CLIENT);
        let metadata = RequestMetadata::from_connection(true, None, peer, &HeaderMap::new()).expect("no metadata");
        assert!(metadata.secure_transport);

        let peer = connect_info(CLIENT);
        let metadata = RequestMetadata::from_connection(false, None, peer, &HeaderMap::new()).expect("no metadata");
        assert!(!metadata.secure_transport);
    }

    #[test]
    fn a_request_without_connection_information_has_no_metadata() {
        assert_eq!(RequestMetadata::from_connection(true, None, None, &HeaderMap::new()), None);
    }

    /// With no forwarding configured, the header is not read at all -- however plausible it
    /// looks.
    #[test]
    fn the_header_is_ignored_when_no_proxy_is_trusted() {
        assert_eq!(source_ip_of(PROXY, &headers(&["203.0.113.10"])), PROXY);
    }

    /// A client connecting directly can send whatever it likes; its own address stands.
    #[test]
    fn an_untrusted_peer_cannot_spoof_the_header() {
        let spoofed = headers(&["192.0.2.99"]);

        assert_eq!(forwarded_source_ip_of(CLIENT, &spoofed), CLIENT);
    }

    /// A request forwarded by one trusted proxy is attributed to the address that proxy recorded.
    #[test]
    fn a_trusted_proxy_reports_the_client() {
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["203.0.113.10"])), CLIENT);
    }

    /// Every hop appends the address it accepted the request from, so a chain of trusted proxies
    /// is walked back to the first address that is not itself a proxy.
    #[test]
    fn a_chain_of_trusted_proxies_is_walked_back_to_the_client() {
        // client, proxy-1 -- the peer is proxy-2, which appended proxy-1.
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["203.0.113.10, 10.0.0.2"])), CLIENT);

        // The entries may arrive as separate header lines rather than one comma-separated value.
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["203.0.113.10", "10.0.0.2"])), CLIENT);
    }

    /// A client that sends its own header has its entries appear to the left of the trusted
    /// proxy's, where they are ignored.
    #[test]
    fn entries_left_of_the_client_are_ignored() {
        let spoofed = headers(&["192.0.2.99, 198.51.100.5, 203.0.113.10"]);

        assert_eq!(forwarded_source_ip_of(PROXY, &spoofed), CLIENT);
    }

    /// When every entry names a trusted proxy, the leftmost is the closest thing to a client the
    /// chain reports.
    #[test]
    fn an_all_proxy_chain_reports_its_leftmost_entry() {
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["10.0.0.2, 10.0.0.3"])), INNER_PROXY);
    }

    /// A trusted proxy that forwards nothing leaves the request attributed to the proxy itself.
    #[test]
    fn a_trusted_proxy_without_a_header_is_the_source() {
        assert_eq!(forwarded_source_ip_of(PROXY, &HeaderMap::new()), PROXY);
    }

    /// Proxies vary in how they write an entry; ports and brackets are accepted, and mapped
    /// addresses are unwrapped just as peer addresses are.
    #[test]
    fn forwarded_entries_may_carry_ports_or_brackets() {
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["203.0.113.10:443"])), CLIENT);
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["::ffff:203.0.113.10"])), CLIENT);

        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["[2001:db8::1]:443"])), v6);
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["[2001:db8::1]"])), v6);
    }

    /// The chain cannot be followed past an entry that names no address -- RFC 7239's `unknown`
    /// or an obfuscated identifier, for instance -- so the request is attributed to the last hop
    /// that did name one.
    #[test]
    fn an_unparseable_entry_stops_the_walk() {
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["203.0.113.10, unknown, 10.0.0.2"])), INNER_PROXY);
        assert_eq!(forwarded_source_ip_of(PROXY, &headers(&["unknown"])), PROXY);
    }

    /// A listener reachable only through its load balancer may believe every peer, which it says
    /// explicitly.
    #[test]
    fn every_peer_can_be_trusted_explicitly() {
        let trust_all = ForwardedForConfig::builder()
            .trusted_proxies(vec!["0.0.0.0/0".to_string(), "::/0".to_string()])
            .build()
            .resolve()
            .expect("failed to resolve forwarded_for configuration");
        let peer = connect_info(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

        let metadata = RequestMetadata::from_connection(true, Some(&trust_all), peer, &headers(&["203.0.113.10"]))
            .expect("no metadata");

        assert_eq!(metadata.source_ip, CLIENT);
    }

    /// A listener may name a header other than `X-Forwarded-For`.
    #[test]
    fn the_header_name_is_configurable() {
        let real_ip = ForwardedForConfig::builder()
            .header("x-real-ip")
            .trusted_proxies(vec!["10.0.0.0/8".to_string()])
            .build()
            .resolve()
            .expect("failed to resolve forwarded_for configuration");

        let mut request_headers = HeaderMap::new();
        request_headers.append("x-real-ip", "203.0.113.10".parse().expect("invalid header value"));
        // The conventional header is not the configured one, so it is not read.
        request_headers.append("x-forwarded-for", "192.0.2.99".parse().expect("invalid header value"));

        let metadata = RequestMetadata::from_connection(true, Some(&real_ip), connect_info(PROXY), &request_headers)
            .expect("no metadata");

        assert_eq!(metadata.source_ip, CLIENT);
    }
}
