
import logging, sys

from protocol.FLOR import FLOR
from codetiming import Timer
from stats.handler_size import *

class EncapsClient:

    def __init__(self, client_id, pk, shares_secret_input, g_ri, tau_ij):
        self.client_id = client_id
        self.pk = pk
        self.shares_secret_input = shares_secret_input
        self.g_ri = g_ri
        self.tau_ij = tau_ij

        pass


class Client:

    def __init__(self, parameter):
        self.logger = logging.getLogger("FLOR." + __name__)
        self.pk = 0
        self.sk = 0
        self.parameter = parameter
        self.shares_secret_input = 0
        self.g_ri = 0
        self.tau_ij = 0
        self.tt = Timer(text="", logger=None)
        self.time_client = {0: 0, 1: 0, 2:0, 3:0, 4:0}
        self.bytes_out = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0 }
        self.bytes_in = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        pass

    def generate_keys(self):
        self.tt.start()
        self.sk, self.pk = FLOR.keygen(self.parameter)
        result = self.tt.stop()
        #print("client {}  took {} - {} {}".format(id(self), result, self.sk, self.pk))
        self.time_client[0] = result
        #print("id {} pk: {}".format(id(self), total_size(self.pk)))
        self.bytes_out[0] += total_size(self.pk)
        #print("id {} selfbytes: {}".format(id(self), self.bytes_out[0]))
        

    def SGEN(self, secret_input, public_key_servers):
        # self.bytes_in[1] += total_size(secret_input)
        self.bytes_in[1] = total_size(public_key_servers)
        self.logger.debug("client {} secret_input {} public_key_servers {}".format(id(self), secret_input, public_key_servers))
        self.tt.start()
        self.shares_secret_input, self.g_ri, self.tau_ij = FLOR.SGen(secret_input, self.sk, self.parameter.THREASHOLD, public_key_servers, self.parameter)
        result = self.tt.stop()
        self.logger.debug("client {} g_ri {}  ".format(id(self), self.g_ri))
        self.logger.debug("client {} tau_ij {}".format(id(self), self.tau_ij))
        #logger.debug("parameters {}".format(parameters))
        self.time_client[1] = result
        encaps_client = EncapsClient(id(self), self.pk, self.shares_secret_input, self.g_ri, self.tau_ij), self.shares_secret_input
        self.bytes_out[1] += total_size(encaps_client) - total_size(id(self))
        
        # print("pk:"+ str(total_size(self.pk)))
        # print("xij1:"+ str(total_size(self.shares_secret_input[0][0])))
        # print("xij2:"+ str(total_size(self.shares_secret_input[0][1])))
        # print("xij:"+ str(total_size(self.shares_secret_input[0])))
        # print("Ri:"+ str(total_size(self.g_ri)))
        # print("tauij:"+ str(total_size(list(self.tau_ij)[0])))
        # print("\n")

        return encaps_client



