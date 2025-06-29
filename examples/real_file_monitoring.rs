use positron_edr::collectors::file_monitor::FileMonitor;
use positron_edr::{init_logging, Result};
use positron_edr::collectors;
use positron_edr::events::{self, SecurityEvent};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    println!("Starting real file monitoring DEMO...");
    println!("Monitoring /tmp directory for file changes");

    let (tx, mut rx) = mpsc::unbounded_channel::<SecurityEvent>();

    let mut monitor = FileMonitor::new(tx, "demo-agent".to_string());

    let monitor_path = if std::path::Path::new("/tmp").exists() {
        "/tmp"
    } else {
        "."
    };

    monitor.start_monitoring(monitor_path)?;
    println!("File monitor started on : {}", monitor_path);

    let event_handler = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            println!("\nReal Event Detected: ");
            println!("Type: {:?}", event.event_type);
            println!("Severity: {:?}", event.severity);
            println!("Description: {:?}", event.description);
            println!("JSON: {}", event.to_json().unwrap_or("Error".to_string()));
        }
    });

    println!("\n🧪 Creating test files to trigger events...");
    
    tokio::spawn(async {
        sleep(Duration::from_secs(2)).await;
        
        let test_dir = if std::path::Path::new("/tmp").exists() {
            "/tmp/positron_test"
        } else {
            "./positron_test"
        };
        
        // Create directory
        let _ = fs::create_dir_all(test_dir);
        
        // Create some files
        let _ = fs::write(format!("{}/normal_file.txt", test_dir), "Hello World");
        sleep(Duration::from_millis(500)).await;
        
        let _ = fs::write(format!("{}/suspicious.exe", test_dir), "Fake executable");
        sleep(Duration::from_millis(500)).await;
        
        let _ = fs::write(format!("{}/script.ps1", test_dir), "Get-Process");
        sleep(Duration::from_millis(500)).await;
        
        // Modify a file
        let _ = fs::write(format!("{}/normal_file.txt", test_dir), "Modified content");
        sleep(Duration::from_millis(500)).await;
        
        // Delete a file
        let _ = fs::remove_file(format!("{}/normal_file.txt", test_dir));
        
        println!("✅ Test file operations completed");
    });
    
    // Run for 10 seconds
    println!("⏰ Monitoring for 10 seconds... Try creating/modifying files!");
    sleep(Duration::from_secs(20)).await;
    
    // Stop monitoring
    monitor.stop_monitoring();
    event_handler.abort();
    
    println!("\n✅ Demo completed!");
    Ok(())
}