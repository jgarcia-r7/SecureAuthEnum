# SecureAuthEnum
SecureAuthEnum: Enumerate user accounts against a SecureAuth SSO portal.
## Description:  
The script will first do a GET request to the target url to determine if it's indeed a SecureAuth SSO poral and if it's vulnerable. Currently, AFAIK, only the password-less portals are vulnerable. Valid usernames are written to an output file. 

## Usage:  
```bash
git clone https://github.com/jgarcia-r7/SecureAuthEnum
pip3 install -r requirements.txt
./SecureAuthEnum.py
```
**SecureAuthEnum.py** takes the following parameters:  
```bash
  -h, --help            show this help message and exit
  -t TARGET_URL, --target_url TARGET_URL
                        Target URL REQUIRED
  -u USERS, --users USERS
                        Users list REQUIRED
  -o OUTPUT, --output OUTPUT
                        Output file name OPTIONAL (Defualt: valid_users.txt)
  -c, --check_only      Check if portal is vulnerable
```

## Examples:  
Check only (Vulnearble):  
![image](https://user-images.githubusercontent.com/81575551/162826112-12b1dfa8-0694-47f8-9b0a-4502cf17be5b.png)

Check only (Not Vulnerable):  
![image](https://user-images.githubusercontent.com/81575551/162826232-128953f6-f0db-4c3c-ac4c-86b78af0310e.png)

Enumerating users:  
![image](https://user-images.githubusercontent.com/81575551/162826370-f06edc75-6fa8-4ec6-b825-4b7cf9733d27.png)
