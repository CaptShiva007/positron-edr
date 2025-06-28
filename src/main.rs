use positron_edr::{init_logging, PositronError, Result};
use positron_edr::events::{SecurityEvent, EventType, Severity};

fn main() -> Result<()> {
    init_logging();

    println!("Starting Positron-EDR...");

    test_json_handling()?;
    test_file_ops()?;
    test_custom_errors()?;

    //Events module
    test_events_system()?;

    println!("All tests passed! Positron-EDR is working!");

    Ok(())    
}

fn test_json_handling() -> Result<()> {
    println!("Testing JSON handling...");

    let data = serde_json::json!({
        "event": "test",
        "timestamp": "2025-07-01T00:00:00Z"
    });

    let _json_string = serde_json::to_string(&data)?;
    println!("JSON serialization works!");

    Ok(())
}

fn test_file_ops() -> Result<()> {
    println!("Testing file operations...");

    match std::fs::read_to_string("nonexisting_file.txt") {
        Ok(_) => println!("Unexpected: File exists!!!"),
        Err(e) => {
            let positron_error = PositronError::from(e);
            println!("Handled File Error: {}", positron_error)
        }
    }

    Ok(())
}

fn test_custom_errors() -> Result<()> {
    println!("Testing custom errors...");

    let custom_error = PositronError::Message("This is a test error".to_string());
    println!("Custom error created: {}", custom_error);

    Ok(())
}

#[allow(dead_code)]
fn simulate_error() -> Result<()> {
    
    Ok(())
}

fn test_events_system() -> Result<()> {
    println!("Testing comprehensive events systems...");

    let file_event = SecurityEvent::file_event(
        EventType::FileCreated, 
        "/tmp/suspicious_file.exe",
        "agent-001".to_string()
    );
    println!("File event: {}", file_event.to_json()?);

    let mut process_event = SecurityEvent::process_event(
        EventType::ProcessStarted, 
        "powershell.exe", 
        1234, 
        "agent-001".to_string()
    );
    process_event.add_detail("command_line", "powershell.exe -enc SGVsbG8gV29ybGQ=");
    println!("Process event: {}", process_event.to_json()?);

    let network_event = SecurityEvent::network_event(
        EventType::NetworkConnectionEstablished, 
        "192.168.1.100", 
        "10.0.0.1:443", 
        "agent-001".to_string()
    );
    println!("Network Event: {}", network_event.to_json()?);

    let auth_event = SecurityEvent::auth_event(
        EventType::LoginFailure, 
        "admin", 
        Severity::Medium, 
        "agent-001".to_string()
    );
    println!("Auth event: {}", auth_event.to_json()?);

    let registry_event = SecurityEvent::registry_event(
        EventType::RegistryKeyModified, 
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
        Some("MaliciousStartup"), 
        "agent-windows-001".to_string(),
    );
    println!("Registry event: {}", registry_event.to_json()?);

    let linux_event = SecurityEvent::linux_sys_event(
        EventType::SudoUsage, 
        "User attempted sudo access", 
        Severity::Medium, 
        "agent-linux-001".to_string(),
    );
    println!("Linux event: {}", linux_event.to_json()?);

    let security_event = SecurityEvent::security_alert(
        EventType::MalwareDetected, 
        "Trojan.Win32.Generic", 
        Severity::Critical, 
        "agent-001".to_string(),    
    );
    println!("Security alert created: {}", security_event.to_json()?);

    Ok(())
}
