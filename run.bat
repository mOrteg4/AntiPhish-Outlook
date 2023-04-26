rem This batch file installs dependencies and starts the server
rem Install Python dependencies
pip install -r requirements.txt

rem Allow network access for WebView control
CheckNetIsolation LoopbackExempt -a -n="microsoft.win32webviewhost_cw5n1h2txyewy" 

rem Change to application directory by opening the folder and copy the path, then paste it here and remove the " "
cd C:\Users\super\Documents\GitHub\AntiPhish-Outlook

rem Start the server
npm run start