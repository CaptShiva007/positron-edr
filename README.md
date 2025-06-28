# 🚀 POSITRON-EDR

## What is POSITRON-EDR?

**POSITRON-EDR** is an experimental, open-source Endpoint Detection and Response (EDR) project built from scratch in **Rust**. The goal is to gain a deep understanding of how modern defensive cybersecurity tools operate, while building a fast, secure, and transparent EDR solution.

---

## 🎯 Why Build an EDR?

Reverse engineering and offensive security often require **understanding what you're up against**. EDRs are a core component of modern defense-in-depth strategies, and they’re getting smarter every year. So…

* To break defenses, you must first **understand them**.
* Building an EDR from the ground up demystifies its internals.
* It’s an opportunity to explore **real-world OS-level security**, **event telemetry**, and **threat detection logic**.

Also because why not? It’s fun.

---

## 🦀 Why Rust?

Rust offers:

* **Memory safety without a garbage collector**
* **Zero-cost abstractions** that allow writing high-performance, low-level code
* A growing ecosystem in the **security community**

It’s ideal for building EDR components that need to be **safe, fast, and close to the metal**.

---

## 🧱 Project Roadmap

This is a learning-first project, but here's a rough roadmap of how development might proceed:

### ✅ Phase 1: Foundation

* [x] Set up basic Rust CLI project
* [x] Design modular architecture (sensor, logger, rules engine)
* [x] Define event types and data structures

### 🚧 Phase 2: System Monitoring

* [ ] File activity monitoring (creation, deletion, modification)
* [ ] Process monitoring (start/stop, command line capture)
* [ ] Registry monitoring (Windows only)

### 🧠 Phase 3: Detection Logic

* [ ] Write basic detection rules (e.g., suspicious process tree)
* [ ] Add rule matching engine
* [ ] Start logging alerts with metadata

### 🔐 Phase 4: Hardening & Evasion Awareness

* [ ] Add tamper protection mechanisms
* [ ] Detect common evasion techniques (e.g., DLL injection, hollowing)
* [ ] Log attempts to disable or bypass EDR

### 🌐 Phase 5: Communication

* [ ] Design local logging and alerting format (JSON/flat files)
* [ ] Add remote telemetry option (gRPC, HTTP API)

---

## 📚 Tech Stack

* **Language**: Rust
* **OS Support**: Starting with Windows, Linux (Mac later?)
* **Logging**: `serde_json`, `log`, `tracing`
* **System APIs**: Windows API, `winapi`, `sysinfo`, `ntapi`

---

## 🤓 Learning Goals

This project will help me:

* Understand **OS internals** and API hooking
* Explore **process/thread/file system** events in depth
* Learn how detection logic is built and deployed
* See how attackers evade detection and how defenders catch them

---

## ✨ Status

This is a **work in progress**, but I’m excited to see where it goes.

> “The best way to understand a system is to build one.”

---

## 🔜 Coming Soon

* Dev blog series on lessons learned
* Sample detections
* Evasion test cases
* Community contributions?
