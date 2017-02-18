# xmanager
Graphical GNU/Linux Server Management script with Zenity</br>
Designed and tested in a Debian 9

![alt text] (xmanager.png)

##Instalation
```
#!/bin/bash
git clone https://github.com/m4n3dw0lf/xmanager
chmod +x $PWD/xmanager.sh
cp $PWD/xmanager.sh /usr/local/bin/xmanager.sh
xmanager.sh
```

##Features

 - Can be used with ssh -X (X11 Forwarding)
 - User information (X Information about user)
 - Software information (X Information about Kernel and Distribution)
 - Hardware information (X Information about hardware)
 - Firewall management (X Rules creation and profiles loading)
 - Service management (X Stop, start, restart machine running services)
 - Package management (X Reconfigure, reinstall, uninstall packages)
 - SCP Download and Upload (Download/Upload file in a remote server)
 - Run script (X script selection to be executed)
