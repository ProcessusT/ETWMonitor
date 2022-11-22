# ETWMonitor

<div align="center">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <br>
</div>

> Windows notifier tool that detects suspicious connections by monitoring ETW event logs<br />
<br />
<br>
<div align="center">
  Server dashboard screen :<br />
<img src="https://github.com/Processus-Thief/ETWMonitor/raw/main/assets/ETWMonitor_server.PNG" width="80%;">
<br /><br />
Crowdsec integration with IP address reputation :<br />
<img src="https://github.com/Processus-Thief/ETWMonitor/raw/main/assets/ETWMonitor_server2.PNG" width="80%;">
<br />
</div>
<br>


## Changelog
<br />
On last version (V 2.3) :<br />
- Crowdsec IP reputation integration (match ip in TCPIP logs)<br />
- Alerts can be sent by email<br />
- Statistics in server dashboard rely on real data<br />
- Correction of bug that keeps CPU usage over 90%<br />
<br />
V 2.1 :<br />
- Client updates detection rules defined in a server XML file automatically<br />
- No more compilation required for new rules creation<br />
<br />
V 2.0 :<br />
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
- You can download latest compiled version from <a href="https://github.com/Processus-Thief/ETWMonitor/releases">Release page</a><br />
Also see installations instructions here : <a href="https://github.com/Processus-Thief/ETWMonitor/blob/main/ETW%20Monitor%20-%20How%20to%20install%20client-server%20version.pdf">INSTALLATION HOW TO.pdf</a>
<br><br>
<br>
    
## Future improvements

<br />
- Include more protocols detections<br />
- Make statistics work in server dashboard (⭐ DONE !!!)<br />
- Build a Client-Server version with Agents and a collector server (⭐ DONE !!!)<br />
- Client updates detection rules defined on server side (⭐ DONE !!!)<br />
<br /><br />

## Maintainability
<br />
Desktop version is no more maintained.<br />
Only client-version will be maintained to get faster updates.<br />
You can still add Agent version updates to Desktop version manually if needed.<br />
<br />
