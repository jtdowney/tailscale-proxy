use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_aux::prelude::*;

#[derive(Deserialize, Debug)]
#[non_exhaustive]
pub enum BackendState {
    NoState,
    NeedsLogin,
    NeedsMachineAuth,
    Stopped,
    Starting,
    Running,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PeerStatus {
    #[serde(rename = "ID")]
    pub id: String,
    pub public_key: String,
    #[serde(rename = "HostName")]
    pub hostname: String,
    #[serde(rename = "DNSName")]
    pub dnsname: String,
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "UserID")]
    pub user_id: i64,
    #[serde(
        rename = "TailscaleIPs",
        deserialize_with = "deserialize_default_from_null"
    )]
    pub tailscale_ips: Vec<IpAddr>,
    #[serde(default, deserialize_with = "deserialize_default_from_null")]
    pub tags: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_default_from_null")]
    pub primary_routes: Vec<String>,
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub addrs: Vec<String>,
    pub cur_addr: String,
    pub relay: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub created: DateTime<Utc>,
    pub last_write: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_handshake: DateTime<Utc>,
    pub online: bool,
    pub keep_alive: bool,
    pub exit_node: bool,
    pub exit_node_option: bool,
    pub active: bool,
    #[serde(
        rename = "PeerAPIURL",
        deserialize_with = "deserialize_default_from_null"
    )]
    pub peer_api_url: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_default_from_null")]
    pub capabilities: Vec<String>,
    #[serde(
        default,
        rename = "sshHostKeys",
        deserialize_with = "deserialize_default_from_null"
    )]
    pub ssh_hostkeys: Vec<String>,
    #[serde(default)]
    pub sharee_node: bool,
    pub in_network_map: bool,
    pub in_magic_sock: bool,
    pub in_engine: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TailnetStatus {
    pub name: String,
    #[serde(rename = "MagicDNSSuffix")]
    pub magic_dns_suffix: String,
    #[serde(rename = "MagicDNSEnabled")]
    pub magic_dns_enabled: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: i64,
    pub login_name: String,
    pub display_name: String,
    #[serde(rename = "ProfilePicURL")]
    pub profile_pic_url: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Status {
    pub version: String,
    pub backend_state: BackendState,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<IpAddr>,
    #[serde(rename = "Self")]
    pub self_status: PeerStatus,
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub health: Vec<String>,
    pub current_tailnet: Option<TailnetStatus>,
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub cert_domains: Vec<String>,
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub peer: HashMap<String, PeerStatus>,
    pub user: HashMap<i64, UserProfile>,
}

#[derive(Deserialize, Debug, Copy, Clone)]
#[non_exhaustive]
pub enum ServiceProto {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "peerapi4")]
    PeerAPI4,
    #[serde(rename = "peerapi6")]
    PeerAPI6,
    #[serde(rename = "peerapi-dns-proxy")]
    PeerAPIDNS,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    pub proto: ServiceProto,
    pub port: u16,
    pub description: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Hostinfo {
    #[serde(rename = "OS")]
    pub os: Option<String>,
    #[serde(rename = "OSVersion")]
    pub os_version: Option<String>,
    pub hostname: Option<String>,
    pub services: Option<Vec<Service>>,
    #[serde(default, rename = "sshHostKeys")]
    pub ssh_hostkeys: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    pub name: String,
    pub user: i64,
    pub sharer: Option<i64>,
    pub key: String,
    pub key_expiry: DateTime<Utc>,
    pub machine: String,
    pub disco_key: String,
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<String>,
    pub endpoints: Option<Vec<SocketAddr>>,
    #[serde(rename = "DERP")]
    pub derp: Option<String>,
    pub hostinfo: Hostinfo,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub primary_routes: Vec<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub online: Option<bool>,
    pub keep_alive: Option<bool>,
    pub machine_authorized: Option<bool>, // TODO: Check the upstream code if this has changed to MachineStatus
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub computed_name: String,
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub computed_name_with_host: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Whois {
    pub node: Node,
    pub user_profile: UserProfile,
    #[serde(default)]
    pub caps: Vec<String>,
}

pub struct Certificate(pub Vec<u8>);
pub struct PrivateKey(pub Vec<u8>);
