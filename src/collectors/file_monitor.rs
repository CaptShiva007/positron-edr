use crate::Result;
use crate::events::{EventType, SecurityEvent, Severity};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::path::Path;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

#[derive(Debug)]
pub struct FileMonitor {
    //channel to send events to
    event_sender: mpsc::UnboundedSender<SecurityEvent>,
    //FS watcher
    watcher: Option<notify::RecommendedWatcher>,
    //Agent Identifier
    agent_id: String,
}

impl FileMonitor {
    pub fn new(event_sender: mpsc::UnboundedSender<SecurityEvent>, agent_id: String) -> Self {
        Self {
            event_sender,
            watcher: None,
            agent_id,
        }
    }

    pub fn start_monitoring<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        info!("Starting file monitoring on: {}", path.display());

        let sender = self.event_sender.clone();
        let agent_id = self.agent_id.clone();

        //create watcher
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    if let Some(security_event) = convert_fs_event_to_security_event(&event, &agent_id) {
                        if let Err(e) = sender.send(security_event) {
                            error!("Failed to send event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("File system watch error: {}", e);
                }
            }
        })?;

        watcher.watch(path, RecursiveMode::Recursive)?;
        self.watcher = Some(watcher);

        Ok(())
    }

    pub fn stop_monitoring(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            drop(watcher);
            info!("Stopped file monitoring");
        }
    }
}

fn convert_fs_event_to_security_event(event: &Event, agent_id: &str) -> Option<SecurityEvent> {
    let path = event.paths.first()?.to_string_lossy();

    let (event_type, severity) = match &event.kind {
        EventKind::Create(_) => {
            if is_suspicious_file(&path) {
                (EventType::FileCreated, Severity::High)
            } else {
                (EventType::FileCreated, Severity::Info)
            }
        }
        EventKind::Modify(_) => (EventType::FileModified, Severity::Info),
        EventKind::Remove(_) => (EventType::FileDeleted, Severity::Info),
        _ => return None,
    };

    let mut security_event = SecurityEvent::file_event(
        event_type, 
        &path, 
        agent_id.to_string()
    );

    security_event.add_detail("event_kind", &format!("{:?}", event.kind));
    security_event.add_detail("file_extension", get_file_extension(&path));

    let mut final_event = security_event;
    final_event.severity = severity;

    Some(final_event)
}

fn is_suspicious_file(path: &str) -> bool {
    let suspicious_extensions = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".dll"];
    let suspicious_names = ["autorun.inf", "desktop.ini"];

    let path_lower = path.to_lowercase();

    for ext in &suspicious_extensions {
        if path_lower.ends_with(ext) {
            return true;
        }
    }

    for name in &suspicious_names {
        if path_lower.contains(name) {
            return true;
        }
    }

    false
}

fn get_file_extension(path: &str) -> &str {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("unknown")
}