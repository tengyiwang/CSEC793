import socket
import sys
import Shamir
import random
import Util
import time
shamir = Shamir.Shamir()
host = socket.gethostname()
port = 9999
baseport = 10000
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.bind((host, baseport))
client_socket.listen(128)


class Client():
    inputs = None
    n_servers = None
    T = None
    R = None
    S = None
    formated_masked_inputs = None
    raw = None
    operation = None

    def __init__(self, operation, n_servers, inputs) -> None:
        self.n_servers = n_servers
        self.inputs = inputs
        self.operation = operation
        print("Client: raw input = ", self.inputs)
        self.raw = self.inputs[-1]
        if operation == "mul":
            for i in range(-2, -len(self.inputs) - 1, -1):
                self.raw *= self.inputs[i]
        elif operation == "sub":
            for i in range(-2, -len(self.inputs) - 1, -1):
                self.raw -= self.inputs[i]

    def log(self, function):
        print(
            f"--------------------Client {function.__name__} starts--------------------")
        function()
        print(
            f"--------------------Client {function.__name__} ends--------------------")

    def notify(self):
        honest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        honest_server.connect((host, port))
        honest_server.send(str(1).encode("utf-8"))
        print("Client: notification from HS: ",
              honest_server.recv(1024).decode("utf-8"))
        honest_server.close()

    def run(self):
        self.log(self.notify)
        self.log(self.receive_random)
        self.log(self.mask_inputs)
        self.log(self.get_final_results)

    def get_final_results(self):
        honest_server, addr = client_socket.accept()
        result = Util.recv_int(honest_server)
        print(f"Client: raw inputs are ", self.inputs)
        print(f"Client: the correct result should be ", self.raw)
        print(
            f"***************Client: received result = {result}***************")

    def send_inputs(self):
        Util.send_to_every_server(
            self.formated_masked_inputs, self.n_servers, host, baseport)

    def mask_inputs(self):
        print(f"Client: there will be {len(self.inputs)} of clients")
        for i in range(len(self.inputs)):
            self.formated_masked_inputs = list()
            self.formated_masked_inputs.append(i + 1)  # client id
            # whether negative
            self.formated_masked_inputs.append(1 if self.inputs[i] < 0 else 0)
            self.formated_masked_inputs.append(
                (self.inputs[i] - self.R[i]) % shamir._PRIME)
            print("Client : masked inputs = ", self.formated_masked_inputs)
            self.log(self.send_inputs)

    def receive_random(self):
        tlist = [list() for i in range(len(self.inputs))]
        rlist = [list() for i in range(len(self.inputs))]
        slist = [list() for i in range(len(self.inputs))]
        for i in range(len(self.inputs)):
            tlist[i] = [list() for j in range(self.n_servers)]
            rlist[i] = [list() for j in range(self.n_servers)]
            slist[i] = [list() for j in range(self.n_servers)]
        for i in range(self.n_servers):
            templist = Util.once_recv_int_list(client_socket)
            print("Client: random list = ", templist)
            for j in range(len(self.inputs)):
                tlist[j][templist[0] - 1].append(templist[0])
                tlist[j][templist[0] - 1].append(templist[3 * j + 1])
                rlist[j][templist[0] - 1].append(templist[0])
                rlist[j][templist[0] - 1].append(templist[3 * j + 2])
                slist[j][templist[0] - 1].append(templist[0])
                slist[j][templist[0] - 1].append(templist[3 * j + 3])
        self.R = [int() for i in range(len(self.inputs))]
        self.T = [int() for i in range(len(self.inputs))]
        self.S = [int() for i in range(len(self.inputs))]
        print("tlist = ", tlist)
        print("rlist = ", rlist)
        print("slist = ", slist)
        for i in range(len(self.inputs)):
            self.T[i] = shamir.recover_secret(tlist[i])
            self.R[i] = shamir.recover_secret(rlist[i])
            self.S[i] = shamir.recover_secret(slist[i])
            print(f"Client: r[{i}], t[{i}], s[{i}] received: ",
                  self.R[i], self.T[i], self.S[i])
            if self.T[i] == self.R[i] * self.S[i] % shamir._PRIME:
                print("Client: t == rs % p, continue to the next step")
                Util.send_to_every_server(1, self.n_servers, host, baseport)
                Util.socket_send(1, host, 9999)
            else:
                print("Client: t != rs % p, try again")
                Util.send_to_every_server(0, self.n_servers, host, baseport)
                Util.socket_send(0, host, 9999)
                exit(0)


low = int(-(1e10))
high = int(1e10)
client = Client(operation="mul", n_servers=2, inputs=[
                random.randint(low, high) for i in range(5)])
client.run()
