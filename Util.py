import hmac
import socket
import Shamir
import random

mmax = 1000000000
shamir = Shamir.Shamir()


def md5(mackey, msg):
    return hmac.new(str(mackey).encode("utf-8"), str(msg).encode("utf-8"), digestmod="md5")


def socket_send(var, host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host, port))
    server.send(str(var).encode("utf-8"))
    server.close()


def formattolist(recv):
    recv = recv.strip("[")
    recv = recv.strip("]")
    recv = recv.strip("(")
    recv = recv.strip(")")
    recv = recv.split(", ")
    return recv


def once_recv_int_list(server):
    client, addr = server.accept()
    inputs = formattolist(client.recv(mmax).decode("utf-8"))
    # inputs = inputs[1:len(inputs) - 1]
    inputs = list(map(int, inputs))
    client.close()
    return inputs


def once_recv_float_list(server):
    client, addr = server.accept()
    inputs = formattolist(client.recv(mmax).decode("utf-8"))
    # inputs = inputs[1:len(inputs) - 1]
    inputs = list(map(float, inputs))
    client.close()
    return inputs


def recv_int(client):
    ans = int(client.recv(mmax).decode("utf-8"))
    return ans


def formattorecover(varlist: list):
    ans = list()
    for i in range(1, len(varlist) + 1):
        temp = [i]
        temp.append(varlist[i - 1])
        ans.append(temp)
    return ans


def generatehmacshare(hmac: hmac.HMAC, n):
    shamir = Shamir.Shamir()
    dec = int(hmac.hexdigest(), 16) % shamir._PRIME
    ans_share = shamir.run(2, dec)
    return ans_share


def send_to_every_server(var, n, host, baseport):
    for i in range(1, n + 1):
        socket_send(var, host, baseport + i)


class Generator():
    def __init__(self, operation) -> None:
        self.operation = operation

    def generate_triples(self, n):
        if self.operation == "mul":
            return self.__mul_triples(n)
        elif self.operation == "sub":
            return self.__sub_triples(n)

    def __sub_triples(self, n):
        ans = dict()
        while len(ans) < n:
            a = random.randint(1, shamir._PRIME)
            b = random.randint(1, shamir._PRIME)
            if a < b:
                a, b = b, a
            if (a, b) in ans:
                continue
            else:
                ans[(a, b)] = (a - b) % shamir._PRIME
        return ans

    def generate_randoms(self, n):
        R = dict()
        while len(R) < n:
            r = random.randint(1, shamir._PRIME)
            if r in R:
                continue
            else:
                s = random.randint(1, shamir._PRIME)
                t = s * r % shamir._PRIME
                R[r] = [s, t]
        return R

    def __mul_triples(self, n):
        ans = dict()
        while len(ans) < n:
            a = random.randint(1, shamir._PRIME)
            b = random.randint(1, shamir._PRIME)
            if (a, b) in ans:
                continue
            else:
                ans[(a, b)] = a * b % shamir._PRIME
        return ans
