import random, logging
import itertools , sys
from parameters.param import *
from cryptography.hazmat.primitives.asymmetric import ec
from sss.sharing import *
from cryptography.hazmat.primitives.asymmetric import dh

from tqdm import tqdm

logger = logging.getLogger("FLOR." + __name__)


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def mod_inverse(k, prime):
    k = k % prime
    if k < 0:
        r = egcd(prime, -k)[2]
    else:
        r = egcd(prime, k)[2]
    return (prime + r) % prime

def findsubsets(s, n):
    return list(itertools.combinations(s, n))

class ServerProof:
    def __init__(self, y_j, pi, r_s, rho, pk, server_id=0):
        self.y_j = y_j
        self.pi = pi
        self.r_s = r_s
        self.rho = rho
        self.pk = pk
        self.server_id = server_id
        pass


class FLOR:

    def __init__(self):
        pass

    @staticmethod
    def keygen(parameters):
        sk = parameters.gen_key()
        pk = sk.public_key()
        return sk, pk

    @staticmethod
    def __generate_key_agreements__(sk_client, public_key_servers):
        agreements = {}
        for public_key in tqdm(public_key_servers,leave=False, desc="Server Agg KeyAggrement:"):
            shared_key = sk_client.exchange(ec.ECDH(), public_key)
            agreements[public_key] = shared_key
        return agreements

    @staticmethod
    def __compute__power__(public_key, x, parameters):
        result = pow(public_key.public_numbers().y, x, parameters.Q)
        return result

    @staticmethod
    def __compute__random__power(g_ri, key_agreement, parameters):
        tmp = int.from_bytes(key_agreement, byteorder='big')
        result = pow(g_ri, tmp, parameters.Q)
        return result

    @staticmethod
    def SGen(x, sk_client, t, public_key_servers, parameters):
        logger.debug("x {} sk_cliet {}".format(x, sk_client))
        logger.debug("t {} public_key_servers {}".format(t, public_key_servers))
        logger.debug("parameters {}".format(parameters))
        shares_secret_input = secret_int_to_points(x, t, parameters.NR_SERVER, parameters.Q)

        ri = 1 #random.randint(0, parameters.param.parameter_numbers().p - 2)
        key_agreements = FLOR.__generate_key_agreements__(sk_client, public_key_servers)
        g_ri = pow(parameters.GENERATOR, ri, parameters.Q)


        tau_ij = {}
        for public_key in public_key_servers:
            temp_1 = FLOR.__compute__power__(public_key, x, parameters)
            temp_2 = FLOR.__compute__random__power(g_ri, key_agreements[public_key], parameters)
            tau = (temp_1 * temp_2) % parameters.Q
            tau_ij[public_key] = tau

        return shares_secret_input, g_ri, tau_ij

    @staticmethod
    def aggregate(list_of_client_public_keys, inputs_x, inputs_ri, sever_secret_key, public_key, parameters):
        agreements = FLOR.__generate_key_agreements__(sever_secret_key, list_of_client_public_keys)
        y_j = 0
        pi = 0
        R_sj = 1
        rho_j = 1
        for pk in tqdm(agreements.keys(), leave=False, desc="Server Agg Proof:"):
            y_j = (y_j + inputs_x[pk]) % parameters.Q
            tmp = int.from_bytes(agreements[pk], byteorder='big')
            logger.debug("agreement : {}".format(tmp))
            pi = (pi + tmp) #% parameters.param.parameter_numbers().p
            logger.debug("agreement : {}".format(pi))
            R_sj *= inputs_ri[pk]
            logger.debug("R_sj : {}".format(R_sj))
        rho = 1
        for i in tqdm(list_of_client_public_keys, leave=False, desc="Server Agg Partial:"):
            r_i = inputs_ri[i]
            sum_skj = 0
            for k in agreements.keys():
                if k != i:
                    sum_skj = sum_skj + int.from_bytes(agreements[k], byteorder='big')

            pow_r_i = pow(r_i, sum_skj, parameters.Q)
            rho = (rho * mod_inverse(pow_r_i, parameters.Q)) % parameters.Q

#        for public_key in list_of_client_public_keys:
#            to_compute = (all_sum - int.from_bytes(agreements[public_key], byteorder='big')) % parameters.param.parameter_numbers().p
#            inverse = mod_inverse(to_compute, parameters.param.parameter_numbers().p)
#            rho_j = (rho_j * (pow(inputs_ri[public_key], inverse, parameters.param.parameter_numbers().p))) % parameters.param.parameter_numbers().p

#        print("rho = {}".format(rho))
#        print("rho_j = {}".format(rho_j))

        return ServerProof(y_j, pi, R_sj, rho, public_key)

    @staticmethod
    def __recon_y__(proofs, parameter):
        y = 0
        points = []
        #i = 0
        for proof in proofs:
            point = (proof.server_id, proof.y_j)
            logger.debug("proof.y_j {}".format(proof.y_j))
            y = (y + int(proof.y_j))  # % parameter.return_param().parameter_numbers().p
            points.append(point)
            #i += 1
        y = points_to_secret_int(points, parameter.Q)
        #print("result: {}".format(result))
        return y

    @staticmethod
    def __verify_r_js__(list_of_server_proofs):
        for proof_1 in list_of_server_proofs:
            for proof_2 in list_of_server_proofs:
                if proof_1.r_s != proof_2.r_s:
                    return False
        return True

    @staticmethod

    def __verify__y_partial(y_partials):
        y = 0
        for y_partial in y_partials.values():
            for y_partial_2 in y_partials.values():
                y = y_partial
            if y_partial != y_partial_2:
                return False
        return True, y


    @staticmethod
    def verify(t, data_client, list_of_server_proofs, parameter):

        subsets = findsubsets(list_of_server_proofs, parameter.MU) # generate subsets of size M with t+1 ≤ |M | ≤m

        random_subset = random.choice(subsets)  #select a random subset with size M


        valid = FLOR.__verify_r_js__(random_subset) # Verify if the r_s == r_s'
        assert valid == True

        #y = FLOR.__recon_y__(list_of_server_proofs, parameter)

        subsets = findsubsets(random_subset, t) #subsets T_i of t+1 partial evaluation
        
        y_partials = {}
        for subset in tqdm(subsets, leave=False, desc="Verify Threshold:"):
            y_partial = FLOR.__recon_y__(subset, parameter)
            y_partials[subset] = y_partial
            #print("subset: {} - partial {}".format(id(subset), y_partial))


        valid, y = FLOR.__verify__y_partial(y_partials) # for all the subsets T i of t+1 partial evaluation
        # SS.Recon returns always the same output y
        assert valid == True

        #print(y_partials)

        #for all the |M| subset M_l ⊂ M such that |M_l | = |M | − 1
        subsets_ml = findsubsets(random_subset, parameter.VER)
    
    
        for subset_ml in tqdm(subsets_ml, leave=False, desc="Verify Equation:"):
            tau_j = 1
            tmp1 = 1

            for data in data_client:
                for proof in subset_ml:
                    tau_j = (tau_j * data.tau_ij[proof.pk]) % parameter.Q

            for proof in subset_ml:
                tmp1 = tmp1 * pow(proof.pk.public_numbers().y, y, parameter.Q)
                tmp1 = tmp1 * pow(proof.r_s, proof.pi, parameter.Q)
                tmp1 = (tmp1 * proof.rho) % parameter.Q

            assert tau_j == tmp1

        # print("y:"+ str(sys.getsizeof(y)) +"\n")

        return True, y
