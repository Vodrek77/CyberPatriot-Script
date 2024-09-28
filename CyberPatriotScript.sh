#!/bin/bash

#VARIABLE DECLARATION:
listOperations=(
"1) Manage Users" 
"2) Manage Groups" 
"3) Password Policy"
"4) Activate Firewall" 
"5) Configure PAM" 
"6) Configure Auditd" 
"7) Scan Crontab" 
"8) Processes and Services" 
"9) Full Update" 
)

#MAIN MENU:
#Shows the main menu and options for the script to execute.
mainMenu() {
	echo 'Linux CyberPatriot Script'
	echo 'Written by Ryan George'
	echo
	echo 'Welcome '$username'!'
	echo
	echo 'Please input what you need to do. (0 for multiple)'
	echo
	echo '0) Activate Multiple'
	for ((i=0; i<${#listOperations[@]}; i++)); do
		echo ${listOperations[i]}
	done
	echo
	read input
	case $((input)) in
		0)
		echo
		activateMultiple
		echo
		;;
		
		1)
		echo
		manageUsers
		echo
		;;
		
		2)
		echo
		;;
		
		3)
		echo
		passwordPolicy
		echo
		;;

		4)
		echo
		activateFirewall
		echo
		;;

		5)
		echo
		configurePAM
		echo
		;;
		
		6)
		echo
		configureAuditd
		echo
		;;
		
		7)
		echo
		scanCrontab
		echo
		;;
		
		8)
		echo
		processesAndServices
		echo
		;;
		
		9)
		echo
		fullUpdate
		echo
		;;
		
		*)
		mainMenu
		;;
		esac
	clear
}

#ACTIVATE MULTIPLE:
#Gives the user the option to activate multiple of the options available.
activateMultiple() {
	opList=()
	updateLast=0
	echo 'Hello '$username'! Welcome to Activate Multiple.'
	echo
	echo 'Please enter all the operations you wish to do.'
	echo 'Type 1 number into each line and press enter.'
	echo 'Each command will be documented then activated in order.'
	echo
	echo 'At any time, you can type 0 to start the operations.'
	echo 'You can also get a list of all operations by typing -1.'
	echo
	for ((;;)) do
		echo 'Please input the operation you wish to do. (-1 for list, 0 to Start)'
		read input
		echo
		if [[ ! $input  == 0 ]] && [[ ! $input == -1 ]] && [ ! $input == 4 ]; then
			opList=("${opList[@]}" "$input")
		elif [ $input == -1 ]; then
			for ((i=0; i<${#listOperations[@]}; i++)); do
				echo ${listOperations[i]}
			done
		elif [ $input == 4 ]; then
			updateLast=1
		else
			break
		fi
	done
	if [ $updateLast == 1 ];then
		opList=("${opList[@]}" 4)
	fi
	echo "${opList[@]}"
	echo
	echo 'Activating now!'
	echo
	for ((a=0;a<${#opList[@]}; a++)); do
		case ${opList[a]} in
			1)
			manageUsers
			;;

			2)
			;;

			3)
			passwordPolicy
			;;

			4)
			activateFirewall
			;;
			
			5)
			configurePAM
			;;
		
			6)
			configureAuditd
			;;
			
			7)
			scanCrontab
			;;
			
			8)
			processesAndServices
			;;
			
			9)
			fullUpdate
			;;

			*)
			;;
		esac
	done
	clear
}

#BELOW ARE RESOURCES FOR INDIVIDUAL OPERATIONS!

#MANAGE USERS:
#Establishes the users.txt file that will be used in this function.
manageUsers() 
{
	#Combines files for a full list of expected users
	allUsers=(${authAdmins[@]} ${authUsers[@]})
	
	#Makes a list of what users are on the system currently
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	
	#Checks if there is any unauthorized users on the system
	for user in "${systemUsers[@]}"; do
		found=0
		for authorizedUser in "${allUsers[@]}"; do
        		if [[ "$user" == "$authorizedUser" ]]; then
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then
        		deluser --remove-home "$user"
    		fi
	done
	
	#Re-maps the file to include an updated list of users
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	
	#Gets missing users on the system
	for user in "${allUsers[@]}"; do
    		found=0
    		for sysUser in "${systemUsers[@]}"; do
        		if [[ "$user" == "$sysUser" ]]; then
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then\
        		useradd "$user"
    		fi
	done
	
	#Re-maps the file to include an updated list of users
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	clear
	
	#//////////
	
	#ADMIN USERS
	sudoers=$(grep '^sudo:' /etc/group | cut -d ':' -f 4 | tr ',' '\n')
	
	#Removes any unauthorized Admins
	for user in "${sudoers[@]}"; do
		found=0
		for authorizedUser in "${authAdmins[@]}"; do
        		if [[ "$user" == "$authorizedUser" ]]; then
            			echo "Match Found: $user"
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then
        		echo "Unauthorized user found: $user. Removing..."
        		deluser --remove-home "$user"
    		fi
	done
	
	#Adds any Admins not on the system already
	for user in "${authAdmins[@]}"; do
    		found=0
    		for sudoUser in "${sudoers[@]}"; do
        		if [[ "$user" == "$sudoUser" ]]; then
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then
        		adduser "$user" sudo
    		fi
	done
	clear
	
	#//////////
	
	#PASSWORDS
	echo "Please enter the password you wish to give users."
	echo "DON'T FORGET TO WRITE IT DOWN!"
	read password
	
	for user in "${systemUsers[@]}"; do
		if [[ "$user" != "$username" ]]; then
			echo "$user:$password" | sudo chpasswd
		fi
	done
}

manageGroups()
{
	echo "Still in development"
}

passwordPolicy()
{
	# Backup Configuration Files
	cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
	cp /etc/pam.d/common-auth /etc/pam/common-auth.bak
	cp /etc/login.defs /etc/login.defs.bak
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

	#PAM Password Quality
	sed -i 's/^password.*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 maxclassrepeat=2/' /etc/pam.d/common-password

	#PAM Authentication
	sudo sed -i 's/\(auth \[success=2 default=ignore\] pam_unix.so \)nullok/\1/' /etc/pam.d/common-auth
	echo "auth required pam_tally2.so deny=5 onerr=fail no_lock_time" | tee -a /etc/pam.d/common-auth
	echo "auth required pam_faildelay.so delay=300000" | tee -a /etc/pam.d/common-auth

	#Password Expiry Protocols
	sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
	sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
	sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

	#Root Login + Reset
	sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
	systemctl restart sshd
}

#ACTIVATE FIREWALL:
#Installs and enables uncomplicated firewall on the device.
activateFirewall() 
{
	clear
	echo 'Welcome to Activate Firewall, '$username'.'
	echo
	echo 'This will install and enable Uncomplicated Firewall on this device.'
	echo 'Opening new terminal now...'
	echo
	#mkfifo "$fifo"
	gnome-terminal -- bash -c "
	echo 'Installing Uncomplicated Firewall now!'; 
	sudo apt install ufw; 
	echo 'Installation Complete!'; 
	echo 'Enabling Uncomplicated Firewall now.'; 
	sudo ufw enable; 
	echo; 
	echo 'Firewall has been installed and activated.';
	echo
	echo 'Closing terminal...'
	sleep 2s; > $fifo"
	
	read < "$fifo"
}

#FULL UPDATE:
#Fully updates the device in a seperate terminal.
fullUpdate() 
{
	clear
	echo 'Welcome to Full Update, '$username'.'
	echo
	echo 'This will update all applications on this machine.'
	echo 'Opening new terminal now...'
	echo
	#mkfifo "$fifo"
	
	gnome-terminal -- bash -c "
	echo 'Beginning Update now'; 
	sudo apt-get update -y; 
	sudo apt upgrade -y; 
	echo; 
	echo 'Update Complete!'; 
	echo;
	echo 'Terminal closing...'; 
	sleep 2s; > $fifo"
	
	read < "$fifo"
}

#CONFIGURE PAM:
#Configures PAM to harden the system.
configurePAM() 
{
	#DONT BRICK THE COMPUTER
	echo 'Testing'
}

#CONFIGURE AUDITD:
#Downloads and activates Auditd to help security.
configureAuditd() 
{
	clear
	echo 'Welcome to Configure Auditd, '$username'.'
	echo
	echo 'Installing and activating auditd.'
	echo 'Opening new terminal now...'
	echo
	#mkfifo "$fifo"
	gnome-terminal -- bash -c "
	echo 'Installing auditd.';
	sudo apt install auditd -y;
	echo;
	echo 'Installation Complete!';
	echo 'Activating now.'
	echo;
	sudo auditctl -e 1;
	echo;
	echo 'Activation Complete!';
	echo;
	echo 'Terminal closing...';
	sleep 2s; > $fifo"
	
	read < "$fifo"
}

#SCAN CRONTAB:
#Scans to see if there are any crontabs active. If so, lists them.
scanCrontab() 
{
	clear
	echo 'Welcome to Scan Crontab, '$username'.'
	echo
	echo 'This will see if there are any active crontabs.'
	echo 'If there are any, you can choose to open the file if you want.'
	echo 'Scanning now...'
	echo
	cronDir="/var/spool/cron/crontabs"
	cronRes="ls $cronDir"
	if [ -z "$cronRes" ]; then
		echo 'No active Crontabs.'
	else
		echo 'Crontabs found.'
		echo 'These users have crontabs: '
		echo
		for ((i=0; i<${#authUsers[@]}; i++)); do
			if [ -f $cronDir/"${authUsers[i]}" ]; then
				echo ${authUsers[i]}' has a Crontab, show it? (y/n)'
				read input
				if [ "$input" = "y" ]; then
					echo
					#mkfifo "$fifo"
					echo 'Opening Crontab...'
					gnome-terminal -- bash -c "sudo crontab -u ${authUsers[i]} -e; > $fifo"
					read < "$fifo"
				elif [ "$input" = "n" ]; then
					echo
					echo 'Searching for next user.'
				else
					echo 'Invalid answer, asking again...'
					i=$((i-1))
					echo
				fi
			fi
		done
	fi
}

#PROCESSES AND SERVICES:
#Displays active processes and services as well as options to stop them.
processesAndServices() 
{
	clear
	echo 'Welcome to Processes and Services, '$username'.'
	echo
	echo 'This program will show all active services and processes on this device.'
	echo 'If you want to, you can shut them down as well.'
	echo 'Showing now...'
	echo
	echo 'Processes: '
	netstat -tulnp
	echo
	for ((;;)) do
		echo 'Would you like to remove any process(es)? (y/n)'
		read input
		if [ "$input" == "y" ]; then
			echo 'What process would you like to remove? (By PID)'
			read input
			if [ -f "ps aux | grep -v "grep" | grep $input" ]; then
				kill $input
				echo
				echo 'Process '$input', has been removed.'
				echo
			else
				echo
				echo 'Invalid input.'
				echo
			fi
		elif [ "$input" == "n" ]; then
			echo
			break
		fi
	done
	echo 'Services: '
	service --status-all
	echo
	for ((;;)) do
		echo 'Would you like to stop any services? (y/n)'
		read input
		if [ "$input" == "y" ]; then
			echo 'What service would you like to stop? (By Service Name)'
			read input
			if [ -f "sudo service --status-all | grep $input" ]; then
				apt-get --purge $input
				echo
				echo 'Service '$input', has been stopped.'
				echo
			else
				echo
				echo 'Invalid input.'
				echo
			fi
		elif [ "$input" == "n" ]; then
			echo
			break
		fi
	done
}


#BELOW ARE RESOURCES FOR STARTING THE SCRIPT:

#FIFO TERMINAL:
#Sets up fifo to close unwanted terminals.
fifo="/tmp/terminal_fifo"

#SUDO/ROOT CHECK:
#Checks if the script was ran as root, if not, it exits the script
if [ "$EUID" -ne 0 ]; then
	echo 'Run Script with "sudo" or as root.'
	exit
fi

#USER MANAGER FILE:
#Navigates to create a folder, then
#Creates files that can be used for other methods.

cd /home
mkdir ScriptFiles
cd ScriptFiles

adminFile="manageAdmins.txt"
if [ ! -f "$adminFile" ]; then
	touch manageAdmins.txt
	gedit manageAdmins.txt
fi

userFile="manageUsers.txt"
if [ ! -f "$userFile" ]; then
	touch manageUsers.txt
	gedit manageUsers.txt
fi

#Assigns a list variable for all the users on the system
mapfile -t authUsers < $userFile
mapfile -t authAdmins < $adminFile

allUsers=(${authUsers[@]} ${authAdmins[@]})

echo ${allUsers[@]}

#DBUS CHECK:
#Ensures new terminals can be opened using Gnome
if ! apt list --installed | grep -q "dbus-x11"; then
	echo 'dbus-x11 is not installed. Installing now...'
	apt-get install dbus-x11
	echo
fi

#NETSTAT CHECK:
#Ensures the user has net-tools downloaded for the Processes and Services method.'
if ! apt list --installed | grep -q "net-tools"; then
	echo 'Net-Tools is not installed. Installing now...'
	apt install net-tools
	echo
fi

#USERNAME INPUT:
#Gets the username of the user to later be used.
echo 'What is your Username?'
read username
echo

#INITIALIZE MKFIFO:
#Starts mkfifo to ensure functions and windows open sequentially.
mkfifo $fifo

#PROGRAM START:
#Calls the main menu to start the program.
clear
mainMenu
