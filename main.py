import logging, math, getopt, sys
from datetime import datetime
import time
import random

from parameters.param import Parameters
from codetiming import Timer

from protocol.FLOR import FLOR

from stats.handler_size import *

from client import Client
from server import Server

from tqdm import tqdm



logger = logging.getLogger("FLOR")
logger.setLevel(logging.INFO)


if __name__ == '__main__':
    logger.info("Starting....")
    #security_parameter = 2048
    #param = dh.generate_parameters(generator=2, key_size=security_parameter)
    parameter = Parameters()

    argumentList = sys.argv[1:]

    # Options
    options = "hc:s:m:t:f:v:"

    # Long options
    long_options = ["Help", "Nr_clients =", "Nr_servers =", "MU =", "Threashold_server =",
                    "Fault_clients ="]
    try:
        # Parsing argument
        arguments, values = getopt.getopt(argumentList, options, long_options)

        # checking each argument
        for currentArgument, currentValue in arguments:

            if currentArgument in ("-h", "--Help"):
                print("Diplaying Help")

            elif currentArgument in ("-c", "--Nr_clients"):
                #print("currentValue : {}".format(currentValue))
                parameter.NR_CLIENTS = int(currentValue)

            elif currentArgument in ("-s", "--Nr_Servers"):
                parameter.NR_SERVER = int(currentValue)

            elif currentArgument in ("-m", "--MU"):
                parameter.MU = int(currentValue)
                parameter.VER = parameter.MU - 1

            elif currentArgument in ("-t", "--Threashold_server"):
                parameter.THREASHOLD = int(currentValue) + 1

            elif currentArgument in ("-f", "--Fault_clients"):
                parameter.FAULT = int(currentValue) / 100

            elif currentArgument in ("-v", "--Verification"):
                parameter.VER = int(currentValue) 

    except getopt.error as err:
        # output error, and return with an error code
        print(str(err))

    # parameter.print_parameters_nice()

    list_of_clients = []
    list_of_servers = []

    for i in range(parameter.NR_SERVER):
        s = Server(parameter, i+1)
        s.generate_keys()
        list_of_servers.append(s)

    for i in tqdm(range(parameter.NR_CLIENTS), leave=False, desc="User Keygen:"):
        c = Client(parameter)
        c.generate_keys()
        list_of_clients.append(c)

    public_keys_server = []
    for s in list_of_servers:
        public_keys_server.append(s.pk)
        logger.debug("saving key: {}".format(s.pk))
    logger.debug("Public keys are : {}".format(public_keys_server))



    data_client = []
    for c in tqdm(list_of_clients, leave=False, desc="User SGEN:"):
        secret_input = random.randint(0,2**80)
        # print("x:"+ str(sys.getsizeof(secret_input)))
        encaps_client, shares_secret_input = c.SGEN(secret_input, public_keys_server)
        data_client.append(encaps_client)
        for i in range(parameter.NR_SERVER):
            s = list_of_servers[i]
            s.add_share(c, shares_secret_input[i][1])

    sever_proofs = []
    for (i,s) in tqdm(zip(range(parameter.MU), list_of_servers), leave=False, desc="Server Agg:"):
        proof = s.aggregate(data_client)
        sever_proofs.append(proof)

    
    tt = Timer(text="", logger=None)
    bytes_in_vef = 0 # total_size(parameter.THREASHOLD)
    bytes_in_vef += total_size(data_client)
    
    bytes_in_vef += total_size(sever_proofs)
    
    tt.start()
    verified, value = FLOR.verify(parameter.THREASHOLD, data_client, sever_proofs, parameter)
    
    final_verification = tt.stop()
    bytes_out_vef = 0
    bytes_out_vef += sys.getsizeof(value)

    t = time.localtime()
    current_time = time.strftime("%H_%M_%S", t)
    file_name = "FLOR.csv"
    file_to_save = open(file_name, "a")

    # print("is valid: {}  -  y = {}".format(verified, value))
    time_client = {0: 0, 1: 0, 2: 0}
    data_client_out = {0: 0, 1: 0}
    data_client_in = {0: 0, 1: 0}

    for client in list_of_clients:
        for i in range(0, 2):
            time_client[i] += client.time_client[i]
            # print("id {} took {}".format(id(client), client.time_client[i]))
            data_client_out[i] += client.bytes_out[i]
            data_client_in[i] += client.bytes_in[i]

    for i in range(0, 2):
        time_client[i] = time_client[i] / len(list_of_clients)
        data_client_out[i] = data_client_out[i] / len(list_of_clients)
        data_client_in[i] = data_client_in[i] / len(list_of_clients)

    server = list_of_servers[0]
    # for server in timers.keys():
    str_b = str(parameter.NR_CLIENTS) + ", " + str(parameter.NR_SERVER) + ", " \
        + str(parameter.THREASHOLD - 1) + ", "
    str_b += str(parameter.MU) + ", " + str(parameter.VER) + ", "
    #str_b = "S,"  # "Server: {}\n".format(id(server))
    str_b += str(server.timer_server[0]) + ", "
    str_b += str(time_client[0]) + ", "

    str_b += str(server.bytes_out[0]) + ", "
    str_b += str(data_client_out[0]) + ", "

    #str_b += str(server.timer_server[1]) + ", "
    str_b += str(time_client[1]) + ", "
    str_b += str(data_client_in[1]) + ", "
    str_b += str(data_client_out[1]) + ", "

    str_b += str(server.timer_server[2]) + ", "
    str_b += str(server.bytes_in[2]) + ", "
    str_b += str(server.bytes_out[2]) + ", "

    str_b += str(final_verification) + ", "
    str_b += str(bytes_in_vef) + ", "
    str_b += str(bytes_out_vef)
    print(str_b)
    file_to_save.write(str_b + "\n")
    file_to_save.close()

# The SADI is obtained as "ALL" the server inputs (it's the total amount)
#   Correct SADI ~= USDO * m 

