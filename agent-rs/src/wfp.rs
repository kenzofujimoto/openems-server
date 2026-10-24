//! Anti-bypass network filters in the Windows Filtering Platform. Inside the agent sublayer the
//! highest-weight matching filter decides, so permits for loopback and for this executable outrank
//! the blocks on direct DNS (53), DoT (853) and known DoH addresses. Filters are not persistent and
//! not tied to a dynamic session: they survive a crash (filtering stays on) and vanish at reboot.
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    RemotePort(u16),
    RemoteAddress(IpAddr),
    Loopback,
    AgentApp,
}

#[derive(Debug, Clone)]
pub struct FilterSpec {
    pub name: String,
    pub v6: bool,
    pub action: Action,
    /// 0-15 inside the agent sublayer.
    pub weight: u8,
    pub conditions: Vec<Condition>,
}

impl FilterSpec {
    pub fn addresses(&self) -> impl Iterator<Item = &IpAddr> {
        self.conditions.iter().filter_map(|condition| match condition {
            Condition::RemoteAddress(address) => Some(address),
            _ => None,
        })
    }
}

const LOOPBACK_WEIGHT: u8 = 15;
const AGENT_WEIGHT: u8 = 14;
const DOH_WEIGHT: u8 = 12;
const DNS_WEIGHT: u8 = 10;
const DNS_PORTS: [u16; 2] = [53, 853];
const DOH_PORTS: [u16; 2] = [443, 853];

/// Filters for both address families; `doh` addresses are blocked on 443 and 853 for everyone.
pub fn plan(doh: &[IpAddr]) -> Vec<FilterSpec> {
    let mut filters = Vec::new();
    for v6 in [false, true] {
        let family = if v6 { "IPv6" } else { "IPv4" };
        filters.push(FilterSpec {
            name: format!("openems loopback {family}"),
            v6,
            action: Action::Permit,
            weight: LOOPBACK_WEIGHT,
            conditions: vec![Condition::Loopback],
        });
        for port in DNS_PORTS {
            filters.push(FilterSpec {
                name: format!("openems agent DNS {port} {family}"),
                v6,
                action: Action::Permit,
                weight: AGENT_WEIGHT,
                conditions: vec![Condition::RemotePort(port), Condition::AgentApp],
            });
            filters.push(FilterSpec {
                name: format!("openems block DNS {port} {family}"),
                v6,
                action: Action::Block,
                weight: DNS_WEIGHT,
                conditions: vec![Condition::RemotePort(port)],
            });
        }
        for address in doh.iter().filter(|address| address.is_ipv6() == v6) {
            for port in DOH_PORTS {
                filters.push(FilterSpec {
                    name: format!("openems block DoH {address} {port}"),
                    v6,
                    action: Action::Block,
                    weight: DOH_WEIGHT,
                    conditions: vec![Condition::RemoteAddress(*address), Condition::RemotePort(port)],
                });
            }
        }
    }
    filters
}

/// An outbound connection as WFP classifies it at the ALE connect layer.
#[derive(Debug, Clone)]
pub struct Connection {
    pub remote: IpAddr,
    pub port: u16,
    pub loopback: bool,
    pub agent: bool,
}

/// The agent sublayer's decision, or None when no filter applies.
pub fn verdict(filters: &[FilterSpec], connection: &Connection) -> Option<Action> {
    filters
        .iter()
        .filter(|filter| filter.v6 == connection.remote.is_ipv6())
        .filter(|filter| {
            filter.conditions.iter().all(|condition| match condition {
                Condition::RemotePort(port) => connection.port == *port,
                Condition::RemoteAddress(address) => connection.remote == *address,
                Condition::Loopback => connection.loopback,
                Condition::AgentApp => connection.agent,
            })
        })
        .max_by_key(|filter| filter.weight)
        .map(|filter| filter.action)
}

#[cfg(windows)]
pub use machine::{install, installed_count, remove};

#[cfg(windows)]
mod machine {
    use super::{Action, Condition, FilterSpec, plan};
    use crate::error::{AgentError, Result};
    use std::ffi::c_void;
    use std::net::IpAddr;
    use windows_sys::Win32::Foundation::{
        FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
    };
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
    use windows_sys::core::GUID;

    const PROVIDER_KEY: GUID = GUID::from_u128(0x0b5e9c3a_6d1f_4c2b_9e7a_51d0c4a8f201);
    const SUBLAYER_KEY: GUID = GUID::from_u128(0x0b5e9c3a_6d1f_4c2b_9e7a_51d0c4a8f202);

    fn check(operation: &str, status: u32) -> Result<()> {
        if status == 0 {
            return Ok(());
        }
        Err(AgentError::Local(format!("WFP {operation} failed (0x{status:08x})")))
    }

    fn ignore(status: u32, expected: windows_sys::core::HRESULT) -> u32 {
        if status as i32 == expected { 0 } else { status }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    struct Engine(HANDLE);

    impl Engine {
        fn open() -> Result<Self> {
            let mut handle: HANDLE = std::ptr::null_mut();
            // SAFETY: local engine, default authentication and a non-dynamic session (null).
            let status = unsafe {
                FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), std::ptr::null(), &mut handle)
            };
            check("engine open", status)?;
            Ok(Engine(handle))
        }

        /// All changes commit together or not at all.
        fn transaction(&self, work: impl FnOnce(&Engine) -> Result<()>) -> Result<()> {
            // SAFETY: open engine handle.
            check("transaction begin", unsafe { FwpmTransactionBegin0(self.0, 0) })?;
            match work(self) {
                // SAFETY: a transaction is open on this handle.
                Ok(()) => check("transaction commit", unsafe { FwpmTransactionCommit0(self.0) }),
                Err(error) => {
                    // SAFETY: a transaction is open on this handle.
                    unsafe { FwpmTransactionAbort0(self.0) };
                    Err(error)
                }
            }
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            // SAFETY: handle from FwpmEngineOpen0, closed once.
            unsafe { FwpmEngineClose0(self.0) };
        }
    }

    /// Filter ids this provider owns in one layer.
    fn owned_filters(engine: &Engine, layer: GUID) -> Result<Vec<u64>> {
        let mut provider = PROVIDER_KEY;
        // SAFETY: zeroed template is valid (null pointers, no conditions); fields set below.
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = &mut provider;
        template.layerKey = layer;
        template.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        template.actionMask = 0xFFFF_FFFF;
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: template and out handle are valid for the call.
        check("filter enumerate", unsafe { FwpmFilterCreateEnumHandle0(engine.0, &template, &mut handle) })?;
        let mut ids = Vec::new();
        let outcome = loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut count = 0u32;
            // SAFETY: the engine fills `entries` with `count` filter pointers it allocated.
            let status = unsafe { FwpmFilterEnum0(engine.0, handle, 64, &mut entries, &mut count) };
            if status != 0 {
                break check("filter enumerate", status);
            }
            for index in 0..count as usize {
                // SAFETY: index < count; each entry points to a filter owned by the engine allocation.
                ids.push(unsafe { (**entries.add(index)).filterId });
            }
            if !entries.is_null() {
                // SAFETY: frees the array returned by FwpmFilterEnum0.
                unsafe { FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_FILTER0).cast::<*mut c_void>()) };
            }
            if count < 64 {
                break Ok(());
            }
        };
        // SAFETY: handle from FwpmFilterCreateEnumHandle0.
        unsafe { FwpmFilterDestroyEnumHandle0(engine.0, handle) };
        outcome.map(|()| ids)
    }

    fn remove_owned(engine: &Engine) -> Result<()> {
        for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
            for id in owned_filters(engine, layer)? {
                // SAFETY: id came from the enumeration above.
                let status = unsafe { FwpmFilterDeleteById0(engine.0, id) };
                check("filter delete", ignore(status, FWP_E_FILTER_NOT_FOUND))?;
            }
        }
        Ok(())
    }

    struct AppId(*mut FWP_BYTE_BLOB);

    impl AppId {
        fn current() -> Result<Self> {
            let path = std::env::current_exe()?;
            let path = wide(&path.to_string_lossy());
            let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            // SAFETY: NUL-terminated path; the engine allocates the blob.
            check("app id", unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) })?;
            Ok(AppId(blob))
        }
    }

    impl Drop for AppId {
        fn drop(&mut self) {
            // SAFETY: blob allocated by FwpmGetAppIdFromFileName0, freed once.
            unsafe { FwpmFreeMemory0((&mut self.0 as *mut *mut FWP_BYTE_BLOB).cast::<*mut c_void>()) };
        }
    }

    fn add_filter(engine: &Engine, spec: &FilterSpec, app: &AppId) -> Result<()> {
        let mut name = wide(&spec.name);
        let mut provider = PROVIDER_KEY;
        // Storage referenced by condition pointers must outlive the FwpmFilterAdd0 call.
        let mut addresses: Vec<Box<FWP_BYTE_ARRAY16>> = Vec::new();
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(spec.conditions.len());
        for condition in &spec.conditions {
            // SAFETY: zeroed condition is a valid starting value; fields set below.
            let mut entry: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            match condition {
                Condition::RemotePort(port) => {
                    entry.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    entry.matchType = FWP_MATCH_EQUAL;
                    entry.conditionValue.r#type = FWP_UINT16;
                    entry.conditionValue.Anonymous.uint16 = *port;
                }
                Condition::RemoteAddress(IpAddr::V4(address)) => {
                    entry.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    entry.matchType = FWP_MATCH_EQUAL;
                    entry.conditionValue.r#type = FWP_UINT32;
                    // WFP expects IPv4 addresses in host byte order.
                    entry.conditionValue.Anonymous.uint32 = u32::from(*address);
                }
                Condition::RemoteAddress(IpAddr::V6(address)) => {
                    addresses.push(Box::new(FWP_BYTE_ARRAY16 { byteArray16: address.octets() }));
                    entry.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    entry.matchType = FWP_MATCH_EQUAL;
                    entry.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    entry.conditionValue.Anonymous.byteArray16 =
                        addresses.last_mut().map_or(std::ptr::null_mut(), |boxed| &mut **boxed);
                }
                Condition::Loopback => {
                    entry.fieldKey = FWPM_CONDITION_FLAGS;
                    entry.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    entry.conditionValue.r#type = FWP_UINT32;
                    entry.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                }
                Condition::AgentApp => {
                    entry.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    entry.matchType = FWP_MATCH_EQUAL;
                    entry.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    entry.conditionValue.Anonymous.byteBlob = app.0;
                }
            }
            conditions.push(entry);
        }
        // SAFETY: zeroed filter is valid (no flags, null pointers); fields set below.
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData.name = name.as_mut_ptr();
        filter.providerKey = &mut provider;
        filter.layerKey = if spec.v6 { FWPM_LAYER_ALE_AUTH_CONNECT_V6 } else { FWPM_LAYER_ALE_AUTH_CONNECT_V4 };
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = spec.weight;
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action.r#type = match spec.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        };
        let mut id = 0u64;
        // SAFETY: every pointer in `filter` refers to locals alive for this call.
        check("filter add", unsafe { FwpmFilterAdd0(engine.0, &filter, std::ptr::null_mut(), &mut id) })
    }

    fn add_owner(engine: &Engine) -> Result<()> {
        let mut name = wide("openems agent");
        // SAFETY: zeroed provider is valid; fields set below.
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        provider.providerKey = PROVIDER_KEY;
        provider.displayData.name = name.as_mut_ptr();
        // SAFETY: provider fields refer to locals alive for the call.
        let status = unsafe { FwpmProviderAdd0(engine.0, &provider, std::ptr::null_mut()) };
        check("provider add", ignore(status, FWP_E_ALREADY_EXISTS))?;
        let mut provider_key = PROVIDER_KEY;
        // SAFETY: zeroed sublayer is valid; fields set below.
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = SUBLAYER_KEY;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.providerKey = &mut provider_key;
        sublayer.weight = 0x8000;
        // SAFETY: sublayer fields refer to locals alive for the call.
        let status = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, std::ptr::null_mut()) };
        check("sublayer add", ignore(status, FWP_E_ALREADY_EXISTS))
    }

    /// Replace any filters this agent owns with the current plan, atomically.
    pub fn install(doh: &[IpAddr]) -> Result<()> {
        let app = AppId::current()?;
        let engine = Engine::open()?;
        engine.transaction(|engine| {
            add_owner(engine)?;
            remove_owned(engine)?;
            plan(doh).iter().try_for_each(|spec| add_filter(engine, spec, &app))
        })
    }

    /// Filters this agent's provider currently owns, to detect removal by someone else.
    pub fn installed_count() -> Result<usize> {
        let engine = Engine::open()?;
        let mut total = 0;
        for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
            total += owned_filters(&engine, layer)?.len();
        }
        Ok(total)
    }

    /// Remove the agent's filters, sublayer and provider; absent ones are fine.
    pub fn remove() -> Result<()> {
        let engine = Engine::open()?;
        engine.transaction(|engine| {
            remove_owned(engine)?;
            let sublayer = SUBLAYER_KEY;
            // SAFETY: key pointer valid for the call.
            let status = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &sublayer) };
            check("sublayer delete", ignore(status, FWP_E_SUBLAYER_NOT_FOUND))?;
            let provider = PROVIDER_KEY;
            // SAFETY: key pointer valid for the call.
            let status = unsafe { FwpmProviderDeleteByKey0(engine.0, &provider) };
            check("provider delete", ignore(status, FWP_E_PROVIDER_NOT_FOUND))
        })
    }
}
