#!/bin/bash

# Copyright (c) 2017 Angelo Moura

# This file is part of the program xmanager
# xmanager is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
firewallmax(){
	#LIMPA TODAS AS REGRAS
	iptables -F
	iptables -X
	iptables --flush
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat --flush
	#POLITICAS
	iptables -P INPUT DROP
	iptables -P OUTPUT DROP
	iptables -P FORWARD DROP
	#LIBERA LOOPBACK
	iptables -A INPUT -i lo -d 127.0.0.1 -j ACCEPT
	#APENAS PACOTES ASSOCIADOS A CONEXOES ESTABELECIDAS E RELACIONADAS
	iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	#EXCESSOES A POLITICAS
	#DNS
	iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
	#DHCP
	iptables -A OUTPUT -p udp --dport 67 -j ACCEPT
	#HTTPS
	iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
	#HTTP
	iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
}
firewallmed(){
	iptables -F
	iptables -X
	iptables --flush
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat --flush
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT ACCEPT
	iptables -A INPUT -i lo -d 127.0.0.1 -j ACCEPT
	iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
}
firewallmin(){
	iptables -F
	iptables -X
	iptables --flush
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat --flush
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
}

firewall(){
	OPTION=$(zenity --list --title="xmanager" --column="Services" "Show Rules" "Profile Editor" "Apply new policy...")
        if [[ $? -eq 1 ]]; then
                return 1;
        fi
	if [ "$OPTION" == "Show Rules" ]
  		then
    			LIST=$(iptables -L)
    			echo $LIST > out.txt
    			zenity --text-info --title="xmanager" --filename=out.txt --text="Firewall Rules" --width=600 --height=400
    			rm out.txt

	elif [ "$OPTION" == "Profile Editor" ]
		then
    			MODE=$(zenity --list --title="xmanager" --column="Profile" "Maximum Security" "Medium Security" "Minimum Security")
    			if [ "$MODE" == "Maximum Security" ]
      				then
					firewallmax
					zenity --info --text="Done"
    			elif [ "$MODE" == "Medium Security" ]
      				then
					firewallmed
					zenity --info --text="Done"
    			elif [ "$MODE" == "Minimum Security" ]
      				then
					firewallmin
					zenity --info --text="Done"
			fi

	#CADEIA DE DIALOGOS DO ZENITY PARA PREENCHER UM COMANDO DO IPTABLES
	elif [ "$OPTION" == "Apply new policy..." ]
		then
	        	TABLE=$(zenity --list --title="xmanager" --column="Table" "Default" "NAT")
		        if [[ $? -eq 1 ]]; then
        		        return 1;
        		fi
       	 		ISNAT=""
			OPERATION=""
			CHAIN=""
			PROTOCOL=""
			DHOST=""
			SHOST=""
			DPORT=""
			SPORT=""
			POLICY=""
			NAT=""
			NATPOLICY=""
			NAT_HOST_REDIRECT=""
			NAT_PORT_REDIRECT=""
    			OPERATION=$(zenity --list --title="xmanager" --column="Operation" "Policy" "Add" "Delete")
			if [[ $? -eq 1 ]]; then
                		return 1;
        		fi
			#PREENCHENDO PARAMETROS NAT
    			if [ "$TABLE" == "NAT" ]
				then
					ISNAT="-t nat"
					ISFORWARDING=$(cat /proc/sys/net/ipv4/ip_forward)
					if [ "$ISFORWARDING" == "0" ]
						then
							zenity --info --text="IP Forwarding is disabled!"
					    		ENNAT=$(zenity --list --title="xmanager" --column="Forwarding Option" "Enable" "Disable")
							if [[ $? -eq 1 ]]; then
						                return 1;
        						fi
					fi
				    	if [ "$ENNAT" == "Enable" ]
				        	then
	        					echo 1 > "/proc/sys/net/ipv4/ip_forward"
	    				fi
    					CHAIN=$(zenity --list --title="xmanager" --column="Chain" "PREROUTING" "POSTROUTING")
				        if [[ $? -eq 1 ]]; then
                				return 1;
        				fi
					REDIRECT=$(zenity --entry --title="xmanager" --text="Redirect to IP Address:" --entry-text "")
				        if [[ $? -eq 1 ]]; then
                				return 1;
        				fi
					if [ "$REDIRECT" ]
	  					then
	    						NAT_HOST_REDIRECT="--to-destination $REDIRECT"
					fi
					REDIRECTPORT=$(zenity --entry --title="xmanager" --text="Redirect to port:" --entry-text "")
					if [[ $? -eq 1 ]]; then
                				return 1;
        				fi
					if [ "REDIRECTPORT" ]
	  					then
	    						NAT_PORT_REDIRECT="--to-ports $REDIRECTPORT"
					fi
					NATPOLICY=$(zenity --list --title="xmanager" --column="NAT Policy" "REDIRECT" "DNAT" "SNAT" "ACCEPT" "DROP")
			#PARAMETROS NAO NAT"
    			else
        			CHAIN=$(zenity --list --title="xmanager" --column="Chain" "INPUT" "OUTPUT" "FORWARD")
			        if [[ $? -eq 1 ]]; then
                			return 1;
        			fi
        			POLICY=$(zenity --list --title="xmanager" --column="Default Policy" "ACCEPT" "DROP")
    			fi
	    		if [ "$OPERATION" == "Policy" ]
				then
	    				iptables $ISNAT -P $CHAIN $POLICY
					zenity --info --text="Done"
	    		else
				if [ "$OPERATION" == "Add" ]
					then
				   		OPERATION="-A"
				elif [ "$OPERATION" == "Delete" ]
					then
				 		OPERATION="-D"
				fi
				PROTOCOL=$(zenity --list --title="xmanager" --text="Transport Protocol" --column="Transport Protocol" "tcp" "udp")
			        if [[ $? -eq 1 ]]; then
                			return 1;
        			fi
				#DESTINATION IP
				DH=$(zenity --list --title="xmanager" --text "Destination IP Address" --column="Destination IP Address" "All" "Add")
				if [[ $? -eq 1 ]]; then
                			return 1;
        			fi
				if [ "$DH" == "Add" ]
		  			then
		    				DHOST=$(zenity --entry --title="xamanager" --text="Destination IP Address:" --entry-text "")
		    				if [ "$DHOST" ]
							then
			  					DHOST="-d $DHOST"
						else
							DHOST=""
			   			fi
				fi
				#SOURCE IP
				SH=$(zenity --list --title="xmanager" --text="Source IP Address" --column="Source IP Address" "All" "Add")
			        if [[ $? -eq 1 ]]; then
        			        return 1;
        			fi
				if [ "$SH" == "Add" ]
	  				then
	    					SHOST=$(zenity --entry --title="xamanager" --text="Source IP Address:" --entry-text "")
	    					if [ "$SHOST" ]
							then
			  					SHOST="-d $SHOST"
						else
							SHOST=""
	    					fi
				fi
				#DESTINATION PORT
				DP=$(zenity --list --title="xmanager" --text="Destination Port" --column="Destination Port" "All" "Add")
			        if [[ $? -eq 1 ]]; then
                			return 1;
        			fi
				if [ "$DP" == "Add" ]
		  			then
		    				DPORT=$(zenity --entry --title="xamanager" --text="Destination Port:" --entry-text "")
		    				if [ "$DPORT" ]
							then
			  					DPORT="--dport $DPORT"
						else
							DPORT=""
			   			fi
				fi
				#SOURCE PORT
				SP=$(zenity --list --title="xmanager" --text="Source Port" --column="Source Port" "All" "Add")
			        if [[ $? -eq 1 ]]; then
                			return 1;
        			fi
				if [ "$SP" == "Add" ]
	  				then
	    					SPORT=$(zenity --entry --title="xamanager" --text="Source Port:" --entry-text "")
	    					if [ "$SPORT" ]
							then
			  					SPORT="--sport $SPORT"
						else
							SPORT=""
	    					fi
				fi
				#COMANDO FINAL
				iptables $ISNAT $OPERATION $CHAIN -p $PROTOCOL $DHOST $SHOST $DPORT $SPORT -j $POLICY $NATPOLICY $NAT_HOST_REDIRECT $NAT_PORT_REDIRECT
				#Erase '#' for debug \/
				#echo "iptables $ISNAT $OPERATION $CHAIN -p $PROTOCOL $DHOST $SHOST $DPORT $SPORT -j $POLICY $NATPOLICY $NAT_HOST_REDIRECT $NAT_PORT_REDIRECT"
				zenity --info --text="Done, command: iptables $ISNAT $OPERATION $CHAIN -p $PROTOCOL $DHOST $SHOST $DPORT $SPORT -j $POLICY $NATPOLICY $NAT_HOST_REDIRECT $NAT_PORT_REDIRECT."
			fi
		fi
}

inspect_user(){
USER=$(zenity --list --title="xmanager" --column="Username" `cat /etc/passwd | cut -d ":" -f 1` --width=600 --height=400)
if [[ $? -eq 1 ]]; then
	return 1;
fi
#BUSCA INFORMACAO DO USUARIO
USER_GROUPS=$(echo `id $USER`)
echo "-----------------------------------------[INFO]---------------------------------------------" >> out.txt
finger $USER >> out.txt
echo "-----------------------------------------[GROUPS]------------------------------------------" >> out.txt
echo $USER_GROUPS >> out.txt
echo "----------------------------------------------------------------------------------------------" >> out.txt
zenity --text-info --title=$USER --filename=out.txt --text="$USER Info" --width=600 --height=400
rm out.txt
}

download_upload(){
      	MODE=$(zenity --list --title="Opção" --column="Seleção" "Upload" "Download")
	if [ "$MODE" == "Upload" ]
      		then
        		zenity --info --text="Selecione o arquivo para upload."
            		FILE=$(zenity --file-selection --title="Selecione um arquivo")
            		DEST=$(zenity --entry --text="Caminho para enviar o arquivo" --entry-text "Caminho")
            		scp  $FILE $USUARIO@$SERVER:$DEST
            		zenity --info --text="Concluído."
        elif [ "$MODE" == "Download" ]
     		 then
            		zenity --info --text="Selecione pasta para receber o arquivo"
            		FILE=$(zenity --file-selection --directory --title="Selecione um diretório")
            		DEST=$(zenity --entry --text="Caminho do arquivo a ser recebido" --entry-text "Caminho")
		        scp $USUARIO@$SERVER:$DEST $FILE
            		zenity --info --text="Concluído."
	fi
}

services_management(){
SERVICE=$(zenity --list --title "xmanager" --column="Services" `ls /etc/init.d` --width=600 --height=400)
if [[ $? -eq 1 ]]; then
	return 1;
fi
OPTION=$(zenity --list --title "xmanager" --column="Option" --width=600 --height=400 "Status" "Start" "Stop" "Restart" "Reload")
if [ "$OPTION" == "Status" ]
  then
    STATUS=`service $SERVICE status`
    echo $STATUS > out.txt
    zenity --text-info --title=$SERVICE --filename=out.txt --text="STATUS" --width=600 --height=400
    rm out.txt

elif [ "$OPTION" == "Start" ]
  then
    service $SERVICE start
    zenity --info --text="Asked for $SERVICE to start, check status."
elif [ "$OPTION" == "Stop" ]
  then
    service $SERVICE stop
    zenity --info --text="Asked for $SERVICE to stop, check status."

elif [ "$OPTION" == "Restart" ]
  then
    service $SERVICE restart
    zenity --info --text="Asked for $SERVICE to restart, check status."

elif [ "$OPTION" == "Reload" ]
  then
    sudo service $SERVICE reload
    zenity --info --text="Asked for $SERVICE to reload, check status."
fi
}

inspect_hardware(){
		NCID=$(lspci -k | grep "Network controller" |cut -d " " -f 1)
		ECID=$(lspci -k | grep "Ethernet controller" |cut -d " " -f 1)
		GLXID=$(lspci -k | grep "VGA compatible controller" | cut -d " " -f 1)
		MBID=$(lspci -k | grep "Host bridge" | cut -d " " -f 1)
		HARDWARE=$(zenity --list --title="xmanager" --column="Device" "CPU" "Network controller" "Ethernet controller" "VGA compatible controller" "Host bridge" --width=600 --height=400)
		if [ "$HARDWARE" == "CPU" ]
			then
				CPU=$(lscpu)
				echo $CPU > out.txt
				zenity --text-info --title="xmanager" --filename=out.txt --text="CPU information" --width=600 --height=400
				rm out.txt
		elif [ "$HARDWARE" == "Network controller" ]
			then
				PCIID=$(lspci -k -s $NCID)
				echo $PCIID > out.txt
				zenity --text-info --title="xmanager" --filename=out.txt --text="Network controller information" --width=600 --height=400
				rm out.txt
		elif [ "$HARDWARE" == "Ethernet controller" ]
			then
				PCIID=$(lspci -k -s $ECID)
				echo $PCIID > out.txt
				zenity --text-info --title="xmanager" --filename=out.txt --text="Ethernet controller information" --width=600 --height=400
				rm out.txt
		elif [ "$HARDWARE" == "VGA compatible controller" ]
			then
				PCIID=$(lspci -k -s $GLXID)
				echo $PCIID > out.txt
				zenity --text-info --title="xmanager" --filename=out.txt --text="VGA compatible controller" --width=600 --height=400
				rm out.txt
		elif [ "$HARDWARE" == "Host bridge" ]
			then
				PCIID=$(lspci -k -s $MBID)
				echo $PCIID > out.txt
				zenity --text-info --title="xmanager" --filename=out.txt --text="Host bridge" --width=600 --height=400
				rm out.txt
		fi

}

inspect_software(){
	echo "Inspect the Kernel and memory and stuff"
	OPTION=$(zenity --list --title="xmanager" --text="Software Information" --column="Section"  "Kernel" "Distro")
	if [ "$OPTION" == "Kernel" ]
		then
			KINFO=$(uname -r)
			echo $KINFO > out.txt
			zenity --text-info --title="xmanager" --filename=out.txt --text="Kernel Information" --width=600 --height=400
			rm out.txt
	elif [ "$OPTION" == "Distro" ]
		then
			DINFO=$(lsb_release -a)
			echo $DINFO > out.txt
			zenity --text-info --title="xmanager" --filename=out.txt --text="Distribution Information" --width=600 --height=400
			rm out.txt
	fi
}

manage_packages(){
	SW=$(dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2)
	SOFTWARE=$(zenity --list --title="xmanager" --text="Installed Packages" --column="Installed Packages" $SW --width=600 --height=400)
	if [[ $? -eq 1 ]]; then
		return 1;
	fi
	OPTION=$(zenity --list --title="xmanager" --text="Options" --column="Option" "Information" "Reconfigure" "Uninstall" "Reinstall")
	if [ "$OPTION" == "Information" ]
		then
			PKT=$(apt show $SOFTWARE)
			echo $PKT > out.txt
			zenity --text-info --title="xmanager" --filename=out.txt --text="Package Information" --width=600 --height=400
			rm out.txt
	elif [ "$OPTION" == "Reconfigure" ]
		then
		if [[ $EUID -ne 0 ]]
		  then
		    zenity --info --text="Need to run with root privileges"
		    continue
		fi
		dpkg-reconfigure $SOFTWARE
	elif [ "$OPTION" == "Uninstall" ]
		then
		if [[ $EUID -ne 0 ]]
		  then
		    zenity --info --text="Need to run with root privileges"
		    continue
		fi
		apt-get purge $SOFTWARE
	elif [ "$OPTION" == "Reinstall" ]
		then
		if [[ $EUID -ne 0 ]]
		  then
		   zenity --info --text="Need to run with root privileges"
		   continue
		fi
		apt-get --reinstall $SOFTWARE
	fi

}

runscript(){
	zenity --info --text="Select the script"
	FILE=$(zenity --file-selection --title="xmanager")
	.$FILE
}

manage_user(){
        if [[ $EUID -ne 0 ]]
                then
                        zenity --info --text="Need to run with root privileges"
                        return 1;
                fi
        OPTION=$(zenity --list --title="xmanager" --text="Options" --column="Option" "Create User" "Delete User" "Add user into group" "Remove user from group" "Change user password" "Read user history" --width=600 --height=400)
        if [ "$OPTION" == "Create User" ]
                then
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
                        ENTRY=$(zenity --title "User Creation" --username --password)
                        USERNAME=$(echo $ENTRY | cut -d '|' -f1)
                        PASSWORD=$(echo $ENTRY | cut -d '|' -f2)
                        useradd $USERNAME -m -d /home/$USERNAME
                        echo $USERNAME:$PASSWORD | chpasswd
        elif [ "$OPTION" == "Delete User" ]
                then
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
                        USER=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `cat /etc/passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
                        userdel $USER
        elif [ "$OPTION" == "Add user into group" ]
                then
                        USER=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `cat /etc/passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
                        SYSGROUPS=`cat /etc/group | cut -d : -f 1`
                        GROUP=$(zenity --list --title="xmanager" --text="Select Group" --column="Group" $SYSGROUPS --width=600 --height=400)
                        usermod -aG $GROUP $USER
        elif [ "$OPTION" == "Remove user from group" ]
                then
                        USER=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `cat /etc/passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
                        USERGROUPS=$(groups $USER | cut -d ":" -f 2)
                        GROUP=$(zenity --list --title="xmanager" --text="Select Group" --column="Group" $USERGROUPS --width=600 --height=400)
                        gpasswd -d $USER $GROUP
	elif [ "$OPTION" == "Read user history" ]
		then
                        USRNAME=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `cat /etc/passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			cp /home/$USRNAME/.bash_history out.txt
			zenity --text-info --title="xmanager" --filename=out.txt --text="$USRNAME History" --width=600 --height=400
			rm out.txt
	elif [ "$OPTION" == "Change user password" ]
		then
                        USRNAME=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `cat /etc/passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			NEWPASSWD=$(zenity --title="xmanager" --password --text="New Password")
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			CNEWPASSWD=$(zenity --title="xmanager" --password --text="Confirm New Password")
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			if [ "$NEWPASSWD" == "$CNEWPASSWD" ]
				then
                			echo $USRNAME:$NEWPASSWD | chpasswd
					zenity --info --text="Done."
			else
				zenity --info --text="Passwords don't match."
			fi
        fi
}

while true
	do
  		ans=$(zenity --list --title "xmanager" --text "by: m4n3dw0lf" --column "Service" --width=600 --height=400 "User Information" "User Management" "Software Information" "Hardware Information" "Firewall Management" "Services Management" "Package Management" "Download/Upload" "Run Script" "Exit")

 		if [ "$ans" == "User Information" ]
    			then
      				inspect_user
		elif [ "$ans" == "User Management" ]
			then
				manage_user
  		elif [ "$ans" == "Software Information" ]
    			then
      				inspect_software
  		elif [ "$ans" == "Hardware Information" ]
    			then
      				inspect_hardware
  		elif [ "$ans" == "Firewall Management" ]
    			then
				if [[ $EUID -ne 0 ]]
	 	 			then
	    					zenity --info --text="Need to run with root privileges"
	    					continue
	  			fi
      				firewall
  		elif [ "$ans" == "Package Management" ]
    			then
      				manage_packages
  		elif [ "$ans" == "Services Management" ]
    			then
				if [[ $EUID -ne 0 ]]
	  				then
	    					zenity --info --text="Need to run with root privileges"
            					continue
	  			fi
      				services_management
		elif [ "$ans" == "Download/Upload" ]
    			then
      				download_upload
  		elif [ "$ans" == "Run Script" ]
    			then
      				runscript
  		elif [ "$ans" == "Exit" ]
    			then
      				exit
  		else
    			exit
  		fi
	done


