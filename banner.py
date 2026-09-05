import socket


def grab_banner(ip, port):

    try:

        s = socket.socket()

        s.settimeout(2)

        s.connect((ip, port))

        banner = s.recv(1024)

        s.close()

        return banner.decode(errors="ignore")

    except:

        return "Banner Not Available"