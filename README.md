# ETWMonitor

<div align="center">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <br>
</div>

> Windows notifier tool that detects RDP, SMB, WinRM and RPC connections by monitoring ETW event logs<br />
<br />
<br>
<div align="center">
  Server monitoring screen :<br />
<img src="https://github.com/Processus-Thief/ETWMonitor/raw/main/assets/ETWMonitor_server.PNG" width="80%;">
<br /><br />
  Client Toast notification in Desktop version :<br />
<img src="https://github.com/Processus-Thief/ETWMonitor/raw/main/assets/Connexion_SMB.PNG" width="80%;">
</div>
<br>


## Changelog
<br />
On last version (V 2.0) :<br />
- Client-server support<br />
- Client agent launched on startup as Windows service<br />
<br />
V 1.1 :<br />
- Detect and notify WinRM connections<br />
<br />
V 1.0 :<br />
- Detect and notify RDP, SMB and RPC connections<br />

<br /><br />

## What da fuck is this ?
<br />
On Windows, ETW (for Event Tracing for Windows) is a mechanism to trace and log events that are raised<br />
by user-mode applications and kernel-mode drivers.<br />
ETWMonitor monitors events in real time to detect suspicious network connections.<br />
<br />
<br />

## Installation
<br>
- You can download latest compiled version from <a href="https://github.com/Processus-Thief/ETWMonitor/releases">Release page</a>
<br><br>
<br>
    
## Future improvements

<br />
- Include more protocols detections<br />
- Build a Client-Server version with Agents and a collector server (⭐ DONE !!!)
