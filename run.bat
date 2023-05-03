rem This batch file installs dependencies and starts the server
rem Install Python dependencies
cd /d %~dp0
rem pip install -r "%~dp0requirements.txt"

rem Allow network access for WebView control
CheckNetIsolation LoopbackExempt -a -n="microsoft.win32webviewhost_cw5n1h2txyewy" 

rem Change to application directory by opening the folder and copy the path, then paste it here and remove the " "
cd "%~dp0"

rem Start the server
npm run start