#!/bin/bash

firewall_logging(){
	iptables -A INPUT -p tcp --dport 22 -j LOG -m state --state NEW --log-level debug --log-prefix "[+] SSH Connection: "
	iptables -A INPUT -p icmp --icmp-type echo-request -j LOG -m limit --limit 1/s --log-level debug --log-prefix "[+] ICMP request: "
	iptables -A INPUT -p icmp --icmp-type echo-reply -j LOG -m limit --limit 1/s --log-level debug --log-prefix "[+] ICMP reply: "
	iptables -A INPUT -p udp --dport 67 -j LOG --log-level debug --log-prefix "[+] DHCP Client: "
	iptables -A INPUT -p udp --sport 67 -j LOG --log-level debug --log-prefix "[+] DHCP Server: "
	iptables -A INPUT -p udp --dport 53 -j LOG --log-level debug --log-prefix "[+] DNS Client: "
	iptables -A INPUT -p udp --sport 53 -j LOG --log-level debug --log-prefix "[+] DNS Server: "
}

firewallmax(){
	#LIMPA TODAS AS REGRAS
	iptables -F
	iptables -X
	iptables --flush
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat --flush
	#CHAMA FUNCAO DE LOGGING
	firewall_logging
	#LIBERA LOOPBACK
	iptables -A INPUT -i lo -j ACCEPT
	#APENAS PACOTES ASSOCIADOS A CONEXOES ESTABELECIDAS PELO HOST
        iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

	#PROTECTIONS
	#Tear Drop
	iptables -A INPUT -f -j DROP
	#Syn Flood
	iptables -A INPUT -p tcp --dport 80 --syn -m limit --limit 10/s -j ACCEPT
	iptables -A INPUT -p tcp --dport 80 --syn -j DROP

	#EXCESSOES A POLITICAS
	#HABILITA SSH APENAS PARA UM HOST
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A OUTPUT -p tcp --sport 22 -m state --state RELATED,ESTABLISHED -j ACCEPT
	sourceip=$(dialog --title "xmanager - Firewall Management:" --radiolist "Source IP Address" 0 0 0  "All" "" OFF "Add" "" ON --stdout)
        if [[ $? -eq 1 ]]; then
        	return 1;
        fi
        if [ "$sourceip" == "Add" ]
        	then
			shost=$(dialog --title "xmanager - Firewall Management" --inputbox "WARNING: Enter the single IP Address that will be allowed to connect to this machine: " 0 0 --stdout)
                        iptables -D INPUT -p tcp --dport 22 -j ACCEPT
                        iptables -A INPUT -p tcp --source $shost --dport 22 -j ACCEPT
        fi
	#DNS
	iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
	#DHCP
	iptables -A OUTPUT -p udp --dport 67 -j ACCEPT
	#HTTPS
	iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
	#HTTP
	iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
	#POLITICAS
	iptables -P INPUT DROP
	iptables -P OUTPUT DROP
	iptables -P FORWARD DROP

}

firewallmed(){
	iptables -F
	iptables -X
	iptables --flush
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat --flush
	firewall_logging
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT ACCEPT
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A INPUT -p tcp --dport 22 -j ACCEPT
	iptables -A INPUT -p icmp -j ACCEPT
}

firewallmin(){
	iptables -F
	iptables -X
	iptables --flush
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat --flush
	firewall_logging
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
}


firewall(){
        #Se o usuario eh root
        if [[ $EUID -ne 0 ]];then
                dialog --title 'xmanager' --msgbox 'Need to run with root privileges' 0 0
                return 1;
        fi
	#5 OPCOES PRINCIPAIS DO DIALOGO DE FIREWALL
	option=$(dialog --title "xmanager - Firewall Management:" --radiolist "Option" 0 0 0  "Show Rules" "" ON "Logging" "" OFF "Profile" "" OFF "Apply new policy..." "" OFF "Add Static ARP Entry..." "" OFF "Allow ICMP from host..." "" OFF --stdout)
        if [[ $? -eq 1 ]]; then
                return 1;
        fi
	#MOSTRA REGRAS DE FIREWALL
	if [ "$option" == "Show Rules" ]
  		then
    			list=$(iptables -L)
			dialog --title "xmanager - Firewall Management" --msgbox "$list" 0 0
	#Liberar o ICMP apenas para determinado host
	elif [ "$option" == "Allow ICMP from host..." ]
		then
			ip=$(dialog --title "xmanager - Firewall Management" --inputbox "IP Address: " 0 0 --stdout)
			iptables -A INPUT -p icmp --icmp-type 8 -s $ip -j ACCEPT
			iptables -A OUTPUT -p icmp --icmp-type 0 -d $ip -j ACCEPT
			dialog --title "xmanager - Firewall Management" --msgbox "Done" 0 0
	#Seta uma entrada estatica na tabela ARP
	elif [ "$option" == "Add Static ARP Entry..." ]
		then
			ip=$(dialog --title "xmanager - Firewall Management" --inputbox "IP Address: " 0 0 --stdout)
			mac=$(dialog --title "xmanager - Firewall Management" --inputbox "MAC Address: " 0 0 --stdout)
			arp -s "$ip" "mac"
			dialog --title "xmanager - Firewall Management" --msgbox "Done" 0 0

	elif [ "$option" == "Logging" ]
		then
			dialog --tailbox /var/log/iptables.log 0 0

	#SELECIONA A POLITICA PADRAO DO FIREWALL, MINIMUN, MEDIUM, MAXIMUM (FUNCOES ACIMA)
	elif [ "$option" == "Profile" ]
		then
    			mode=$(dialog --title "xmanager - Firewall Management:" --radiolist "Select the Security Profile: " 0 0 0 "Maximum Security" "" OFF "Medium Security" "" OFF "Minimum Security" "" OFF --stdout)
    			if [ "$mode" == "Maximum Security" ]
      				then
					firewallmax
    			elif [ "$mode" == "Medium Security" ]
      				then
					firewallmed
    			elif [ "$mode" == "Minimum Security" ]
      				then
					firewallmin
			fi
		        if [[ $? -eq 1 ]]; then
		                return 1;
		        fi
			dialog --title "xmanager - Firewall Management" --msgbox "Done" 0 0


	#CADEIA DE DIALOGOS DO ZENITY PARA PREENCHER UM COMANDO DO IPTABLES
	elif [ "$option" == "Apply new policy..." ]
		then
		        if [[ $? -eq 1 ]]; then
        		        return 1;
        		fi
			operation=""
			chain=""
			protocol=""
			dhost=""
			shost=""
			dport=""
			sport=""
			policy=""
			#ADICIONAR OU REMOVER UMA REGRA
			operation=$(dialog --title "xmanager - Firewall Management:" --radiolist "Operation: " 0 0 0 "Chain Policy" "" OFF "Add" "" OFF "Delete" "" OFF --stdout)
			if [[ $? -eq 1 ]]; then
                		return 1;
        		fi
			#CADEIA IPTABLES
			chain=$(dialog --title "xmanager - Firewall Management:" --radiolist "Chain" 0 0 0 "INPUT" "" OFF "OUTPUT" "" OFF "FORWARD" "" OFF --stdout)
			if [[ $? -eq 1 ]]; then
                		return 1;
        		fi
			#POLITICA DE TRATATIVA DO PACOTE
			policy=$(dialog --title "xmanager - Firewall Management:" --radiolist "Default Policy: " 0 0 0 "ACCEPT" "" OFF "DROP" "" OFF "REJECT" "" OFF --stdout)
	    		if [ "$operation" == "Chain Policy" ]
				then
	    				iptables -P $chain $policy
					dialog --title "xmanager - Firewall Management" --msgbox "Done" 0 0
	    		else
				if [ "$operation" == "Add" ]
					then
				   		operation="-A"
				elif [ "$operation" == "Delete" ]
					then
				 		operation="-D"
				fi
				#PROTOCOLO
				protocol=$(dialog --title "xmanager - Firewall Management" --radiolist "Protocol" 0 0 0 "tcp" "" OFF "udp" "" OFF "icmp" "" OFF --stdout)
			        if [[ $? -eq 1 ]]; then
                			return 1;
        			fi
				#DESTINATION IP
				dh=$(dialog --title "xmanager - Firewall Management" --radiolist "Destination IP Address" 0 0 0 "All" "" ON "Add" "" OFF --stdout)
				if [[ $? -eq 1 ]]; then
                			return 1;
        			fi
				if [ "$dh" == "Add" ]
		  			then
						dhost=$(dialog --title "xmanager - Firewall Management" --inputbox "Destination IP Address: " 0 0 --stdout)
		    				if [ "$dhost" ]
							then
			  					dhost="-d $dhost"
						else
							dhost=""
			   			fi
				fi
				#SOURCE IP
				sh=$(dialog --title "xmanager - Firewall Management" --radiolist "Source IP Address" 0 0 0 "All" "" ON "Add" "" OFF --stdout)
			        if [[ $? -eq 1 ]]; then
        			        return 1;
        			fi
				if [ "$sh" == "Add" ]
	  				then
						shost=$(dialog --title "xmanager - Firewall Management" --inputbox "Source IP Address: " 0 0 --stdout)
	    					if [ "$shost" ]
							then
			  					shost="-d $shost"
						else
							shost=""
	    					fi
				fi
				#PORTA DESTINO E ORIGEM CASO O PROTOCOLO NAO SEJA ICMP
				if [ "$PROTOCOL" != "icmp" ]; then
					#DESTINATION PORT
					dp=$(dialog --title "xmanager - Firewall Management" --radiolist "Destination Port" 0 0 0 "All" "" ON "Add" "" OFF --stdout)
			        	if [[ $? -eq 1 ]]; then
                				return 1;
        				fi
					if [ "$dp" == "Add" ]
		  				then
							dport=$(dialog --title "xmanager - Firewall Management" --inputbox "Destination Port: " 0 0 --stdout)
		    					if [ "$dport" ]
								then
			  						dport="--dport $dport"
							else
								dport=""
			   				fi
					fi
					#SOURCE PORT
					sp=$(dialog --title "xmanager - Firewall Management" --radiolist "Source Port" 0 0 0 "All" "" ON "Add" "" OFF --stdout)
			        	if [[ $? -eq 1 ]]; then
                				return 1;
        				fi
					if [ "$sp" == "Add" ]
	  					then
							sport=$(dialog --title "xmanager - Firewall Management" --inputbox "Source Port: " 0 0 --stdout)
	    						if [ "$sport" ]
								then
			  						sport="--sport $sport"
							else
								sport=""
	    						fi
					fi
				fi
				#COMANDO FINAL
				iptables $operation $chain -p $protocol $dhost $shost $dport $sport -j $policy
				dialog --title "xmanager - Firewall Management" --msgbox "Done, command: iptables $operation $chain -p $protocol $dhost $shost $dport $sport -j $policy" 0 0
			fi
		fi
}
#ACABA AS FUNCTIONS DE FIREWALL

inspect_user(){
	USER=$(zenity --list --title="xmanager" --column="Username" `getent passwd | grep home |cut -d ":" -f 1` --width=600 --height=400)
	#Verifica se o usuario pressionou cancel no dialogo zenity
	if [[ $? -eq 1 ]]; then
	        return 1;
	fi
	#Monta a formatacao das informacoes no arquivo out.txt em seguida utiliza ele como entrada do dialogo zenity e depois o remove
	echo "-----------------------------------------[INFO]---------------------------------------------" > out.txt
	finger $USER >> out.txt
	echo "-----------------------------------------[GROUPS]------------------------------------------" >> out.txt
	id $USER >> out.txt
	echo "----------------------------------------------------------------------------------------------" >> out.txt
	zenity --text-info --title=$USER --filename=out.txt --text="$USER Info" --width=600 --height=400
	rm out.txt
}

#Function para gerenciamento de usuarios
manage_user(){
	#Verifica se o usuario possui privilegios de root
        if [[ $EUID -ne 0 ]]
                then
                        zenity --info --text="Need to run with root privileges"
                        return 1;
                fi
	#Dialogo zenity preenche a variavel OPTION com o valor selecionado na lista em seguida o utiliza na cadeia de decisao (if,elif,else) para executar um procedimento
        OPTION=$(zenity --list --title="xmanager" --text="Options" --column="Option" "Create User" "Delete User" "Add user into group" "Remove user from group" "Change user password" "Read user history" --width=600 --height=400)
	#Procedimento que cria usuario
        if [ "$OPTION" == "Create User" ]
                then
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Entrada de dados do usuario que recebe os dois valores no seguinte formato: username|password para criar um usuario
                        ENTRY=$(zenity --title "User Creation" --username --password)
			#Splita o username e passwod em 2 variaveis.
                        USERNAME=$(echo $ENTRY | cut -d '|' -f1)
                        PASSWORD=$(echo $ENTRY | cut -d '|' -f2)
			#Cria o usuario com um diretorio home e com a variavel $SHELL como /bin/bash.
                        useradd $USERNAME -m -d /home/$USERNAME -s /bin/bash
			#One liner para troca de senha de usuario
                        echo $USERNAME:$PASSWORD | chpasswd
			zenity --info --text="User Created."
	#Procedimento que deleta usuario
        elif [ "$OPTION" == "Delete User" ]
                then
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Dialogo zenity que lista usuarios que possuam home para serem selecionados
                        USER=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `getent passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
			#Deleta usuario selecionado
			if zenity --question
				then
                        		userdel $USER
					zenity --info --text="User Deleted."
			fi
	#Procedimento que adiciona usuario a grupo
        elif [ "$OPTION" == "Add user into group" ]
                then
			#Dialogo zenity que lista usuarios que possuam home para serem selecionados
                        USER=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `getent passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Pega os grupos do sistema
                        SYSGROUPS=`getent group | cut -d : -f 1`
			#Dialogo zenity que cria lista com os grupos em SYSGROUPS para serem selecionados
                        GROUP=$(zenity --list --title="xmanager" --text="Select Group" --column="Group" $SYSGROUPS --width=600 --height=400)
			if zenity --question
				then
					#Adiciona o usuario selecionado ao grupo selecionado
                        		usermod -aG $GROUP $USER
					zenity --info --text="User added into group."
			fi
	#Procedimento que remove usuario de grupo.
        elif [ "$OPTION" == "Remove user from group" ]
                then
			#Dialogo zenity que lista usuarios que possuam home para serem selecionados
                        USER=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `getent passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Busca os grupos do usuario
                        USERGROUPS=$(groups $USER | cut -d ":" -f 2)
			#Dialogo zenity que lista os grupos do usuario para serem selecionados
                        GROUP=$(zenity --list --title="xmanager" --text="Select Group" --column="Group" $USERGROUPS --width=600 --height=400)
			if zenity --question
				then
					#Remove usuario do grupo
                        		gpasswd -d $USER $GROUP
					zenity --info --text="User removed from group."
			fi
	#Procedimento que le o .bash_history de um usuario
        elif [ "$OPTION" == "Read user history" ]
                then
			#Dialogo zenity que lista usuarios que possuam home para serem selecionados
                        USRNAME=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `getent passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Dialogo zenity com o bash_history do usuario selecionado
                        zenity --text-info --title="xmanager" --filename=/home/$USRNAME/.bash_history --text="$USRNAME History" --width=600 --height=400
	#Procediento que troca a senha do usuario
        elif [ "$OPTION" == "Change user password" ]
                then
			#Dialogo zenity que lista usuarios em /etc/passwd que possuam home para serem selecionados
                        USRNAME=$(zenity --list --title="xmanager" --text="Select User" --column="Username" `getent passwd | grep home | cut -d ":" -f 1` --width=600 --height=400)
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Dialogo que recebe senha
                        NEWPASSWD=$(zenity --title="New password" --password )
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Checa complexidade da senha
			complexity=$(echo $NEWPASSWD | egrep "^.{8,20}" | egrep "[ABCDEFGHIJKLMNOPQRSTUVWXYZ]" | egrep "[abcdefghijklmnopqrstuvwxyz]" | egrep "[0-9]")
			if [ -z $complexity ]
				then
					zenity --warning --text="Weak password, require min 8 characters including: uppercase, lowercase and number"
					return 1;
			fi
			#Dialogo que recebe confirmacao de senha
                        CNEWPASSWD=$(zenity --title="Confirm new password" --password )
			#Verifica se o usuario pressionou cancel no dialogo zenity
                        if [[ $? -eq 1 ]]; then
                                return 1;
                        fi
			#Verifica se as senhas sao iguais
                        if [ "$NEWPASSWD" == "$CNEWPASSWD" ]
                                then
					#One liner de troca de senha
                                        echo $USRNAME:$NEWPASSWD | chpasswd
                                        zenity --info --text="Password changed."
                        else
                                zenity --info --text="Passwords don't match."
                        fi
        fi
}

lvm_f(){
	opt=$(dialog --title "xmanager" --radiolist "Option" 0 0 0  "Extend Logs LVM" "" OFF "Mount Logs LVM" "" OFF "List LVMs" "" ON --stdout)
	#Extende a LVM de backups
	if [ "$opt" == "Extend Logs LVM" ]; then
		gb=$(dialog --title "xmanager" --inputbox "Number in GBs: " 0 0 --stdout)
		lvextend -L +"$gb"G /dev/mapper/vol_group-logs
		resize2fs /dev/mapper/vol_groups-logs
	#Monta o lvm no /firewall_log
	elif [ "$opt" == "Mount Logs LVM" ]; then
		mount /dev/mapper/vol_group-logs /firewall_log
	#Lista lvms
	elif [ "$opt" == "List LVMs" ]; then
		list=$(lvs)
		dialog --title "xmanager - Firewall Management" --msgbox "$list" 0 0
	fi

}

#Loop Dialog Principal
while true; do
	option=$(dialog --stdout --title 'xmanager'\
	--menu 'Option:' 0 0 0\
	1 "User Information"\
	2 "User Management"\
	3 "Firewall Management"\
	4 "LVM LogSystem Expand"\
	0 "Exit")
	#Se o usuario pressionou cancel
        if [[ $? -eq 1 ]]; then
		break
	fi
	#Opcoes para chamar as respectivas funcoes
	case "$option" in
		1) inspect_user ;;
		2) manage_user ;;
		3) firewall ;;
		4) lvm_f ;;
		0) break ;;
	esac
done
