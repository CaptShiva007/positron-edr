use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    //FS Events
    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,
    FilePermissionChanged,
    DirectoryCreated,
    DirectoryDeleted,

    //Process Events
    ProcessStarted,
    ProcessTerminated,
    ProcessInjection,
    DllLoaded,
    ChildProcessCreated,

    //NW Events
    NetworkConnectionEstablished,
    NetworkConnectionClosed,
    DnsQuery,
    HttpRequest,
    SuspiciousTraffic,

    //Auth Events
    LoginSuccess,
    LoginFailure,
    LogoutEvent,
    PrivilegeEscalation,
    PasswordChanged,

    //Windows Specific
    RegistryKeyCreated,
    RegistryKeyModified,
    RegistryKeyDeleted,
    WindowsServiceStarted,
    WindowsServiceStopped,
    ScheduledTaskCreated,
    
    //Linux Specific
    CronJobCreated,
    SudoUsage,
    PackageInstalled,
    KernelModuleLoaded,
    SystemdServiceChanged,

    //Security Events
    MalwareDetected,
    SuspiciousCommand,
    UnauthorizedAccess,
    DataExfil,
    AntiVirusAlert,
    FireWallBlock,

    //System Events
    SystemStartup,
    SystemShutdown,
    TimeChanged,
    UserCreated,
    UserDeleted,
    GroupMembershipChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {

    pub timestamp: DateTime<Utc>,//When
    pub event_type: EventType,//What
    pub severity: Severity, //How severe
    pub source: String, //who reported
    pub description: String, //what happened
    pub details: HashMap<String, String>,
}

impl SecurityEvent {
    pub fn new(
        event_type: EventType,
        severity: Severity,
        source: String,
        description: String
    ) -> Self {
        Self { 
            timestamp: Utc::now(), 
            event_type, 
            severity, 
            source, 
            description, 
            details: 
            HashMap::new() 
        }
    }

    pub fn add_detail(&mut self, key: &str, value: &str) {
        self.details.insert(key.to_string(), value.to_string());
    }

    pub fn to_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json(json: &str) -> crate::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

impl SecurityEvent {
    pub fn file_event(
        event_type: EventType,
        file_path: &str,
        source: String,
    ) -> Self {
        let mut event = Self::new(
            event_type, 
            Severity::Info, 
            source, 
            format!("File operation on {}", file_path)
    );
    event.add_detail("file_path", file_path);
    event
    }

    pub fn process_event(
        event_type: EventType,
        process_name: &str,
        pid: u32,
        source: String
    ) -> Self {
        let mut event = Self::new(
            event_type, 
            Severity::Info, 
            source,
            format!("Process {} (PID: {})", process_name, pid),
        );
        event.add_detail("process_name", process_name);
        event.add_detail("pid", &pid.to_string());
        event
    }

    pub fn network_event(
        event_type: EventType,
        local_addr: &str,
        remote_addr: &str,
        source: String
    ) -> Self {
        let mut event = Self::new(
            event_type, 
            Severity::Info, 
            source, 
            format!("Network connection {} -> {}", local_addr, remote_addr)
    );
    event.add_detail("local_address", local_addr);
    event.add_detail("remote_address", remote_addr);
    event
    }

    pub fn auth_event(
        event_type: EventType,
        username: &str,
        severity: Severity,
        source: String
    ) -> Self {
        let mut event = Self::new(
            event_type, 
            severity, 
            source, 
            format!("Authentication event for user {}", username),
    );
    event.add_detail("Username", username);
    event
    }

    pub fn registry_event(
        event_type: EventType,
        registry_path: &str,
        value_name: Option<&str>,
        source: String
    ) -> Self {
        let mut event = Self::new(
            event_type, 
            Severity::Info, 
            source, 
            format!("Registry operation on {}", registry_path)
    );
    event.add_detail("registry_path", registry_path);
    if let Some(value) = value_name {
        event.add_detail("value_name", value);
    }
    event
    }

    pub fn linux_sys_event(
        event_type: EventType,
        details: &str,
        severity: Severity,
        source: String
    ) -> Self {
        let mut event = Self::new(
            event_type, 
            severity, 
            source, 
            format!("Linux system event: {}", details)
    );
    event.add_detail("system_details", details);
    event
    }

    pub fn security_alert(
        event_type: EventType,
        threat_name: &str,
        severity: Severity,
        source: String
    ) -> Self {
        let mut event = Self::new(
            event_type, 
            severity, 
            source, 
            format!("Security alert: {}", threat_name)
    );
    event.add_detail("threat_name", threat_name);
    event.add_detail("alert_type", "security");
    event
    }
}