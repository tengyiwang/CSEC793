# 导入 socket、sys 模块
import socket
import random
from tokenize import String
from xml.dom import NOT_SUPPORTED_ERR
import Shamir
import hmac
import Util
import sys

shamir = Shamir.Shamir()
baseport = 10000
honest_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()
honest_server_socket.bind((host, 9999))
honest_server_socket.listen(128)


class HonestServer():
    alpha = None  # global mackey
    operation = None
    n_clients = None
    n_servers = None
    n_computations = None  # one preprocess can hold n_computations times of calculations
    n_triples = None
    n_randoms = None

    def __init__(self, operation: String, n_clients: int, n_servers: int, n_computations: int) -> None:
        self.alpha = random.randint(1, shamir._PRIME)
        self.operation = operation
        self.n_clients = n_clients
        self.n_servers = n_servers
        self.n_computations = n_computations

    def log(self, function):
        print(
            f"--------------------Honest Server: {function.__name__} starts--------------------")
        function()
        print(
            f"--------------------Honest Server: {function.__name__} ends--------------------")

    def online_phase(self):
        while self.n_computations > 0:
            self.n_computations -= 1
            # clients are joining.
            client, addr = honest_server_socket.accept()
            if int(client.recv(1024)) == 1:
                print("Honest Server: client detected!")
                self.log(self.notify_nodes_of_client)
                print("Honest Server: all MPC nodes notified")
                client.send(str(1).encode("utf-8"))
                client.close()

            # clients reporting correct t = rs received
            for j in range(self.n_clients):
                client, addr = honest_server_socket.accept()
                if int(client.recv(1024).decode("utf-8")) == 1:
                    client.close()
                    print(
                        "Honest Server: client reporting random value received, continue the protocol")
                else:
                    # future works
                    exit(0)
            # get outputs
            self.log(self.getoutputs)
        print("Honest Server: raw materials used out, protocol aborted")

    def getoutputs(self):
        print(
            f"Honest Server: {self.n_clients} inputs will be calcualted, {self.n_clients - 1} MAC checks will be performed")
        Z = int()
        negative = -1
        for _ in range(self.n_clients - 1):
            z = [int() for i in range(self.n_servers)]
            macz = [int() for i in range(self.n_servers)]
            r = [int() for i in range(self.n_servers)]
            omega = float()
            for i in range(self.n_servers):
                varlist = Util.once_recv_int_list(honest_server_socket)
                print("HS: varlist = ", varlist)
                serverid = int(varlist[0])
                z[serverid - 1] = varlist[1]
                macz[serverid - 1] = varlist[2]
                r[serverid - 1] = varlist[3]
                if serverid == 1:
                    omega = varlist[4]
                    if len(varlist) == 6:
                        negative = varlist[5]
            z = Util.formattorecover(z)
            macz = Util.formattorecover(macz)
            r = Util.formattorecover(r)
            z = shamir.recover_secret(z)
            print(f"Honest Server: Z = {z} + {omega}")
            Z = (z + omega) % shamir._PRIME
            MACZ = shamir.recover_secret(macz)  # % shamir._PRIME
            R = shamir.recover_secret(r)
            hashz = self.alpha * Z % shamir._PRIME
            print("Honest Server: Z, MACZ, hashz = ", Z, MACZ, hashz)
            if MACZ != hashz:
                print(
                    "Honest Server: **********MAC check failed, protocol aborts**************")
                Util.send_to_every_server(
                    [1, 2], self.n_servers, host, baseport)
                exit(0)
            else:
                print(
                    f"Honest Server: MAC check passed, continue to next steps. Will send Z - R % p = {(Z-R)%shamir._PRIME} back to nodes")
                back_to_server = (Z - R)  # % shamir._PRIME
                Util.send_to_every_server(
                    back_to_server, self.n_servers, host, baseport)
        if self.operation == "sub" and Z > shamir._PRIME / 2:
            negative = 1
        if negative == 1:
            print("Honest Server: negative = ", negative)
            Z -= shamir._PRIME
        print(
            f"Honest Server: the final result is {Z}, sending back to clients")
        Util.socket_send(Z, host, baseport)

    def notify_nodes_of_client(self):
        Util.send_to_every_server(1, self.n_servers, host, baseport)

    def preprocessing(self):
        '''preprocessing phase to reduce burdens during online phase'''
        self.log(self.send_key_operation_and_nclients_servers)
        self.log(self.send_raw_materials)

    def send_raw_materials(self):
        '''send triples and random numbers based on operation'''
        n_triples = (self.n_clients - 1) * self.n_computations
        n_randoms = (2 * self.n_clients - 1) * self.n_computations
        generator = Util.Generator(self.operation)
        TRIPLES = generator.generate_triples(n_triples)
        RANDOMS = generator.generate_randoms(n_randoms)
        A_SHARES = [list() for i in range(self.n_servers)]
        B_SHARES = [list() for i in range(self.n_servers)]
        C_SHARES = [list() for i in range(self.n_servers)]
        R_SHARES = [list() for i in range(self.n_servers)]
        T_SHARES = [list() for i in range(self.n_servers)]
        S_SHARES = [list() for i in range(self.n_servers)]
        MACA_SHARES = [list() for i in range(self.n_servers)]
        MACB_SHARES = [list() for i in range(self.n_servers)]
        MACC_SHARES = [list() for i in range(self.n_servers)]
        print("Honest Server: TRIPLES = ", TRIPLES)
        print("Honest Server: RS = ", RANDOMS)
        for i in TRIPLES:
            a = i[0]
            b = i[1]
            c = TRIPLES[i]
            maca = self.alpha * a % shamir._PRIME
            macb = self.alpha * b % shamir._PRIME
            macc = self.alpha * c % shamir._PRIME
            a_share = shamir.run(self.n_servers, a)
            b_share = shamir.run(self.n_servers, b)
            c_share = shamir.run(self.n_servers, c)
            maca_share = shamir.run(self.n_servers, maca)
            macb_share = shamir.run(self.n_servers, macb)
            macc_share = shamir.run(self.n_servers, macc)
            for j in range(self.n_servers):
                A_SHARES[j].append(a_share[j][1])
                B_SHARES[j].append(b_share[j][1])
                C_SHARES[j].append(c_share[j][1])
                MACA_SHARES[j].append(maca_share[j][1])
                MACB_SHARES[j].append(macb_share[j][1])
                MACC_SHARES[j].append(macc_share[j][1])
        for r in RANDOMS:
            s = RANDOMS[r][0]
            t = RANDOMS[r][1]
            r_share = shamir.run(self.n_servers, r)
            s_share = shamir.run(self.n_servers, s)
            t_share = shamir.run(self.n_servers, t)
            for j in range(self.n_servers):
                R_SHARES[j].append(r_share[j][1])
                S_SHARES[j].append(s_share[j][1])
                T_SHARES[j].append(t_share[j][1])

        # send shares to servers respectively
        for i in range(self.n_servers):
            serverport = baseport + i + 1
            a_share = A_SHARES[i]
            print(f"-----------------a_share for server {i + 1}", a_share)
            b_share = B_SHARES[i]
            print(f"-----------------b_share for server {i + 1}", b_share)
            c_share = C_SHARES[i]
            print(f"-----------------c_share for server {i + 1}", c_share)
            r_share = R_SHARES[i]
            print(f"-----------------r_share for server {i + 1}", r_share)
            s_share = S_SHARES[i]
            print(f"-----------------s_share for server {i + 1}", s_share)
            t_share = T_SHARES[i]
            print(f"-----------------t_share for server {i + 1}", t_share)
            maca_share = MACA_SHARES[i]
            print(
                f"-----------------maca_share for server {i + 1}", maca_share)
            macb_share = MACB_SHARES[i]
            print(
                f"-----------------macb_share for server {i + 1}", macb_share)
            macc_share = MACC_SHARES[i]
            print(
                f"-----------------macc_share for server {i + 1}", macc_share)
            Util.socket_send(a_share, host, serverport)
            Util.socket_send(b_share, host, serverport)
            Util.socket_send(c_share, host, serverport)
            Util.socket_send(r_share, host, serverport)
            Util.socket_send(s_share, host, serverport)
            Util.socket_send(t_share, host, serverport)

            Util.socket_send(maca_share, host, serverport)
            Util.socket_send(macb_share, host, serverport)
            Util.socket_send(macc_share, host, serverport)

    def send_key_operation_and_nclients_servers(self):
        '''send alpha_i, n_clients, n_servers, and operation'''
        alpha_share = shamir.run(n=self.n_servers, sec=self.alpha)
        for i in range(self.n_servers):
            templist = [alpha_share[i][1], self.n_clients,
                        self.n_servers, self.operation]
            Util.socket_send(templist, host, baseport + i + 1)

    def run(self):
        self.log(self.preprocessing)
        self.log(self.online_phase)


HS = HonestServer(operation="mul", n_clients=5, n_servers=2, n_computations=3)
HS.run()
