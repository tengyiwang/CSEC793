# CSEC793 Testification of Outsourcing to Untrusted Cloud Environments Servers

# How to use
Firstly use ```python3 server.py -i (1-n)``` to setup the servers, then use ```python3 honest_server.py``` to start the honest server. Finally, use ```python client.py``` to start the client.

By default, you need to setup 2 servers, 1 honest server, and give clients 5 inputs.

# Args settings
## server.py
 you don't have to modify the server.py file to setup any arguments.

## honest_server.py
set arguments in honest_server.py like the following codes

```HS = HonestServer(operation="mul", n_clients=5, n_servers=2, n_computations=3)```

```HS.run()```

Illustration on arguments:

* n_clients: the length of the raw input you setup in client.py should be the same as this argument
* operation: developed operations are "mul" and "sub".
* n_servers: number of servers, your commands should setup the same number as this argument.
* n_computations: the same settings (servers, clients, operation) can be performed for n_computations times. After you run all servers and honest server, this is the times you can use python3 client.py.

## client.py
An example of running client.py can be as follows
```
low = int(-(1e10))
high = int(1e10)
client = Client(operation="mul", n_servers=2, inputs=[
                random.randint(low, high) for i in range(5)])
client.run()
```
Illustrations on arguments:
* operation: should be the same as that in honest_server.py
* n_servers: should be the same as the in the honest_server.py and commands
* inputs: the length of inputs should be the same as that in honest_server.py's argument: n_clients
