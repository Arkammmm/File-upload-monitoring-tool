# File-upload-monitoring-tool
A simple C program for Windows that tries to detect possible file upload activity by watching file access and network connections made by running applications. Built as a learning project using basic process and network monitoring.

Read this,
COMPILATION
-----------
Visual Studio 2022 GUI
1. Open Visual Studio.
2. Create a Console App (C/C++) project.
3. Add your upload_monitor.c file to the project (Source Files).
4. In Project -> Project Properties -> Linker -> Input -> Additional Dependencies, add:
               advapi32.lib;tdh.lib;ws2_32.lib;shlwapi.lib;iphlpapi.lib;ole32.lib;
5. Build the project (Ctrl+Shift+B).

REQUIREMENTS
------------
- Windows Vista or later
- Administrator privileges
- Visual Studio


DETECTION PARAMETERS
--------------------
- Minimum file size: 8 KB
- Time correlation window: 20 seconds
- File I/O + Network send correlation
- Auto-filters system/temp files


FILES GENERATED
---------------
upload_monitor.exe - Compiled program
uploads.log       - Log file (UTF-16, appended)

STOPPING
--------
Press Ctrl+C or close console window

NOTES
-----
- Real-time monitoring via ETW kernel providers
- Correlates FileIo and TcpIp events by PID
- Requires kernel logger access (admin rights)
