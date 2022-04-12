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
Main use (Enumerating User):  
![image](https://user-images.githubusercontent.com/81575551/162858591-056d6f15-ccc4-4d5e-9bfb-a59365273427.png)

Checking if vulnerable (Vuln):  
![image](https://user-images.githubusercontent.com/81575551/162858707-382a3e4b-e5b8-4f26-9dc0-b23fbd68cab4.png)

Check if vulnerable (Not):  
![image](https://user-images.githubusercontent.com/81575551/162858851-a69a297c-f6a9-4449-be2c-06b54b7d279f.png)
