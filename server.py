
import logging,sys


from stats.handler_size import *

from client import EncapsClient
from protocol.FLOR import *
from codetiming import Timer


class Server:

    def __init__(self, parameter, id):
        self.id = id
        self.pk = 0
        self.sk = 0
        self.parameter = parameter
        self.logger = logging.getLogger("FLOR." + __name__)
        self.shares = {}
        self.timer = Timer(text="", logger=None)
        self.timer_server = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        self.bytes_out = {0: 0, 1: 0, 2: 0}
        self.bytes_in = {0: 0, 1: 0, 2: 0}
        pass

    def generate_keys(self):
        self.timer.start()
        self.sk, self.pk = FLOR.keygen(self.parameter)
        result = self.timer.stop()
        #print("server {}  took {} - {} {}".format(id(self), result, self.sk, self.pk))
        self.timer_server[0] = result
        self.bytes_out[0] += total_size(self.pk)#sys.getsizeof(self.pk)

    def add_share(self, client, share):
        #self.bytes_in[1] += total_size(share)# sys.getsizeof(share)
        self.shares[client.pk] = share


    def aggregate(self, encaps):
        for encap in encaps:
            #self.bytes_in[2] += total_size(encap)#sys.getsizeof(encaps)
            self.bytes_in[2] += total_size(encap.pk)  # sys.getsizeof(encaps)
            self.bytes_in[2] += total_size(encap.shares_secret_input)  # sys.getsizeof(encaps)
            self.bytes_in[2] += total_size(encap.g_ri)  # sys.getsizeof(encaps)
            #self.bytes_in[2] += total_size(encap.tau_ij)  # sys.getsizeof(encaps)

        self.timer.start()
        list_ris = {}
        list_of_client_public_keys = []

        for encap in encaps:
            list_ris[encap.pk] = encap.g_ri
            list_of_client_public_keys.append(encap.pk)

        self.logger.debug("server {} ris {}".format(id(self), list_ris))
        self.logger.debug("server {} pks {}".format(id(self), list_of_client_public_keys))
        proof = FLOR.aggregate(list_of_client_public_keys, self.shares, list_ris ,self.sk, self.pk, self.parameter)
        self.logger.debug("server {} proof.y_j {}".format(id(self), proof.y_j))
        self.logger.debug("server {} proof.pi {}".format(id(self), proof.pi))
        self.logger.debug("server {} proof.r_s {}".format(id(self), proof.r_s))
        self.logger.debug("server {} proof.rho {}".format(id(self), proof.rho))
        result = self.timer.stop()
        proof.server_id = self.id
        proof.pk = self.pk


        self.timer_server[2] = result
        self.bytes_out[2] += total_size(proof.y_j)
        self.bytes_out[2] += total_size(proof.rho)
        self.bytes_out[2] += total_size(proof.pi)
        self.bytes_out[2] += total_size(proof.r_s)

        # print("yj:"+ str(total_size(proof.y_j)))
        # print("rhoj:"+ str(total_size(proof.rho)))
        # print("pij:"+ str(total_size(proof.pi)))
        # print("Rj:"+ str(total_size(proof.r_s)))
        # print("\n")

        return proof

