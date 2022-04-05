import socket
import getopt
import sys
import hmac
import Shamir
import Util
shamir = Shamir.Shamir()
host = socket.gethostname()
baseport = 10000
mmax = int(1e9)
argv = sys.argv[1:]
try:
    opts, args = getopt.getopt(argv, "i:")
except:
    print("Error")
id

for opt, arg in opts:
    if opt in ['-i']:
        id = arg
id = int(id)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = baseport + id
server_socket.bind((host, port))
server_socket.listen(100000)


class Server():
    alpha = None
    operation = None
    n_clients = None
    n_servers = None
    alist = None
    blist = None
    clist = None
    rlist = None
    slist = None
    tlist = None
    macalist = None
    macblist = None
    macclist = None
    negative = None
    inputs = None

    def __init__(self) -> None:
        self.negative = 0
        print(f"Server {id} working on port {port}")

    def log(self, function):
        print(f"----------Server {id}: {function.__name__} starts----------")
        function()
        print(f"----------Server {id}: {function.__name__} ends----------")

    def run(self):
        self.log(self.preprocessing)
        self.log(self.online_phase)

    def calculates(self):
        print("operation = ", self.operation)
        if self.operation == "mul":
            self.log(self.__mul_calculate)
        elif self.operation == "sub":
            self.log(self.__sub_calculate)

    def __sub_calculate(self):
        while len(self.inputs) >= 2:
            list_to_HS = self.__two_input_sub_calculation()
            print("list_to_HS = ", list_to_HS)
            Util.socket_send(list_to_HS, host, 9999)
            # get the results
            varlist = Util.once_recv_int_list(server_socket)
            if len(varlist) > 1:
                print(f"Server {id}: MAC checks failed, protocol aborted")
                exit(0)
            else:
                self.inputs.append(varlist[0])

    def __two_input_sub_calculation(self):
        return self.__two_input_calculation()

    def __two_input_calculation(self):
        print(f"Server {id}: two inputs calculation process starts")
        epsilon = [int() for i in range(self.n_servers)]
        delta = [int() for i in range(self.n_servers)]
        epsilon[id - 1] = (self.rlist[-1] - self.alist[-1])  # % shamir._PRIME
        delta[id - 1] = (self.rlist[-2] - self.blist[-1])  # % shamir._PRIME
        # broadcasts to other servers and receives from other servers
        for i in range(1, self.n_servers + 1):
            if i != id:
                inputs_to_other_servers = [id,
                                           epsilon[id - 1], delta[id - 1]]
                print(
                    f"Server {id}: inputs to other, sending to {i} server: epsilon = {epsilon[id - 1]}, delta = {delta[id - 1]}")
                Util.socket_send(inputs_to_other_servers,
                                 host, baseport + i)
                others = Util.once_recv_int_list(server_socket)
                print("Server: others = ", others)
                epsilon[int(others[0] - 1)] = others[1]
                delta[int(others[0] - 1)] = others[2]

        # calculates EPSILON and DELTA and z
        print(
            f"Server {id}: epsilon list = {epsilon}, delta list = {delta}")
        EPSILON = (shamir.recover_secret(Util.formattorecover(
            epsilon)) + self.inputs[-1])  # % shamir._PRIME
        DELTA = (shamir.recover_secret(
            Util.formattorecover(delta)) + self.inputs[-2])  # % shamir._PRIME
        print(f"Server {id}: EPSILON = {EPSILON}, DELTA = {DELTA}")
        z = self.__z_calculate(EPSILON, DELTA)
        # z = (self.clist[-1] + EPSILON * self.blist[-1] +
        #      DELTA * self.alist[-1]) % shamir._PRIME
        macz = self.__macz_calculate(EPSILON, DELTA)
        list_to_HS = [id, z, macz, self.rlist[-1 - self.n_clients]]
        if id == 1:
            list_to_HS.append(self.__omega_calculate(EPSILON, DELTA))
            if len(self.inputs) == 2:
                list_to_HS.append(self.negative)
        self.rlist.pop()
        self.rlist.pop()
        self.tlist.pop()
        self.tlist.pop()
        self.slist.pop()
        self.slist.pop()
        self.rlist.append(self.rlist[-(self.n_clients - 1)])
        self.tlist.append(self.tlist[-(self.n_clients - 1)])
        self.slist.append(self.slist[-(self.n_clients - 1)])
        self.inputs.pop()
        self.inputs.pop()
        self.alist.pop()
        self.blist.pop()
        self.clist.pop()
        self.macalist.pop()
        self.macblist.pop()
        self.macclist.pop()

        print(f"Server {id}: two inputs calculation process ends")
        return list_to_HS

    def __omega_calculate(self, EPSILON, DELTA):
        if self.operation == "mul":
            return EPSILON * DELTA % shamir._PRIME
        elif self.operation == "sub":
            return (EPSILON - DELTA)  # % shamir._PRIME

    def __z_calculate(self, EPSILON, DELTA):
        if self.operation == "mul":
            return (self.clist[-1] + EPSILON * self.blist[-1] +
                    DELTA * self.alist[-1]) % shamir._PRIME
        elif self.operation == "sub":
            return self.clist[-1]  # % shamir._PRIME

    def __macz_calculate(self, EPSILON, DELTA):
        if self.operation == "mul":
            return (self.macclist[-1] + EPSILON *
                    self.macblist[-1] + DELTA * self.macalist[-1] +
                    self.alpha * EPSILON * DELTA) % shamir._PRIME
        elif self.operation == "sub":
            return (self.macclist[-1] + EPSILON * self.alpha - DELTA * self.alpha) % shamir._PRIME

    def __mul_calculate(self):
        while len(self.inputs) >= 2:
            list_to_HS = self.__two_input_mul_calculation()
            print("list_to_HS = ", list_to_HS)
            Util.socket_send(list_to_HS, host, 9999)
            # get the results
            varlist = Util.once_recv_int_list(server_socket)
            if len(varlist) > 1:
                print(f"Server {id}: MAC checks failed, protocol aborted")
                exit(0)
            else:
                self.inputs.append(varlist[0])

    def __two_input_mul_calculation(self):
        return self.__two_input_calculation()

    def receive_inputs(self):
        self.inputs = [int() for i in range(self.n_clients)]
        self.negative = 0
        for i in range(self.n_clients):
            varlist = Util.once_recv_int_list(server_socket)
            print(f"Server {id}: list from clients received", varlist)
            self.inputs[int(varlist[0] - 1)] = varlist[2]
            if self.operation == "mul" and varlist[1] == 1:
                self.negative ^= 1
        print(f"Server {id}: all inputs received = ", self.inputs)

    def online_phase(self):
        while len(self.alist) > 0:
            honest_server, addr = server_socket.accept()
            if int(honest_server.recv(1024).decode("utf-8")) == 1:
                honest_server.close()
                print(f"Server {id}: client detected")
                self.log(self.send_random_to_client)
                self.log(self.receive_inputs)
                self.calculates()
            else:
                print("protocol abort")
                exit(0)
        print(f"Server {id}: raw materials used out, protocol aborts")

    def send_random_to_client(self):
        varlist = [id]
        for i in range(-self.n_clients, 0):
            varlist.append(self.tlist[i])
            varlist.append(self.rlist[i])
            varlist.append(self.slist[i])
        print("Server varlist = ", varlist)
        Util.socket_send(varlist, host, 10000)
        for i in range(self.n_clients):
            client, addr = server_socket.accept()
            if int(client.recv(1024).decode("utf-8")) == 1:
                print(
                    f"Server {id}: random input correct, continue to the next steps")
            else:
                print(f"Server {id}: random received by client failed, abort")
                exit(0)

    def preprocessing(self):
        '''server preprocessing phase: get raw materials and alpha_i'''
        self.log(self.receive_key_operation_and_nclients_servers)
        self.log(self.receive_raw_materials)

    def receive_raw_materials(self):
        self.alist = Util.once_recv_int_list(server_socket)
        self.blist = Util.once_recv_int_list(server_socket)
        self.clist = Util.once_recv_int_list(server_socket)
        self.rlist = Util.once_recv_int_list(server_socket)
        self.slist = Util.once_recv_int_list(server_socket)
        self.tlist = Util.once_recv_int_list(server_socket)
        self.macalist = Util.once_recv_int_list(server_socket)
        self.macblist = Util.once_recv_int_list(server_socket)
        self.macclist = Util.once_recv_int_list(server_socket)
        print("alist = ", self.alist)
        print("blist = ", self.blist)
        print("clist = ", self.clist)
        print("rlist = ", self.rlist)
        print("slist = ", self.slist)
        print("tlist = ", self.tlist)
        print("macalist = ", self.macalist)
        print("macblist = ", self.macblist)
        print("macclist = ", self.macclist)

    def receive_key_operation_and_nclients_servers(self):
        '''receive basic information from honest server'''
        honest_server_socket, addr = server_socket.accept()
        varlist = Util.formattolist(
            honest_server_socket.recv(mmax).decode("utf-8"))
        self.alpha = int(varlist[0])
        self.n_clients = int(varlist[1])
        self.n_servers = int(varlist[2])
        self.operation = varlist[3].strip("'")
        print(f"Server {id}: alpha = {self.alpha}, n_clients = {self.n_clients}, n_servers = {self.n_servers}, operation = {self.operation}")


server = Server()
server.run()
