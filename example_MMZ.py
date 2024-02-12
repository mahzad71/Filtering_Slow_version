import time
import concrete.numpy as cnp
import numpy as np
import hashlib

# Bitwidth of each chunk and number of chunks in each 32-bit number.
#index = 0
WIDTH, NUM_CHUNKS = 4, 8
assert (WIDTH * NUM_CHUNKS == 32)

def break_down_data(data, data_size):
    all_chunks = [
        [(x >> i * WIDTH) % (2**WIDTH) for i in range(data_size // WIDTH)[::-1]]
        for x in data
    ]
    return all_chunks

def encode(key):
    # Breaking down the data into chunks
    encoded_key = break_down_data(key, 32)
    print("encoded key is:", encoded_key)
    return encoded_key


def _PSI_impl(g_chunk, given_chunk, index):
    intersect = np.sum(np.bitwise_xor(g_chunk, given_chunk) == 0) == NUM_CHUNKS
    print("Encrypted Intersection is :", intersect)
    result = intersect * index
    return result


def chunks_to_uint32(chunks):
    return int(sum([2**((NUM_CHUNKS-1-i)*WIDTH)*x for i, x in enumerate(chunks)]))

def chunks_to_uint32(chunks):
    return int(sum([2**((NUM_CHUNKS-1-i)*WIDTH)*x for i, x in enumerate(chunks)]))

def decode(result, key_chunks):
    if result != 0:
        int_result = chunks_to_uint32(key_chunks)
        return int_result
    else:
        # Handle error or unexpected format
        print(f"Intersection not happened")
        return 0


class HomomorphicPSI:

    # The circuit used to implement the xor_query
    _PSI_circuit: cnp.Circuit
 
                
    def __init__(self):
        #self._state = np.zeros(STATE_SHAPE, dtype=np.int64)

        configuration = cnp.Configuration(
            enable_unsafe_features=True,
            use_insecure_key_cache=True,
            insecure_key_cache_location=".keys",
        )

        PSI_compiler = cnp.Compiler(
            _PSI_impl,
    {"g_chunk": "encrypted", "given_chunk": "encrypted", "index": "clear"}
        )

        inputset_PSI = [
                (

        np.ones(NUM_CHUNKS, dtype=np.int64) * (2 ** WIDTH ),
        np.ones(NUM_CHUNKS, dtype=np.int64) * (2 ** WIDTH ),
        1 ,            
                    
                )
            ]
        
        print()
        print()

        print()

        print("Compiling PSI circuit...")
        start = time.time()
        self._PSI_circuit = PSI_compiler.compile(inputset_PSI, configuration)
        end = time.time()
        print(f"(took {end - start:.3f} seconds)")

        print()


        print("Generating PSI keys...")
        start = time.time()
        self._PSI_circuit.keygen()
        end = time.time()
        print(f"(took {end - start:.3f} seconds)")

        print()

    def PSI(self, g_key, given_key):

        start = time.time()      
        g_key_chunks = encode(g_key)
        given_key_chunks = encode(given_key)
        end = time.time()
        print(f"Encoding (took {end - start:.3f} seconds)")

        all_decrypted_results = []
        decoded_decrypted_results = []
        index = 1  # Initialize the index

        for g_chunk, given_chunk in zip(g_key_chunks, given_key_chunks):
            print("\nProcessing Chunk:", g_chunk, given_chunk, "Index:", index)

            start = time.time()
            encrypted_chunk = self._PSI_circuit.encrypt(g_chunk, given_chunk, index)
            result_chunk = self._PSI_circuit.run(encrypted_chunk)
            end = time.time()
            print(f"Encryption (took {end - start:.3f} seconds)")

            start = time.time()
            decrypted_result = self._PSI_circuit.decrypt(result_chunk)
            end = time.time()
            print(f"Decryption (took {end - start:.3f} seconds)")

            all_decrypted_results.append(decrypted_result)

            print(f"(took {end - start:.3f} seconds)")
            print("Decrypted results for intersecting keys:", all_decrypted_results)

            # Decoding the result
            start = time.time()
            decoded_result = decode(decrypted_result, given_chunk)
            if decoded_result is not None:
                decoded_decrypted_results.append(decoded_result)
            index += 1
            end = time.time()
            print(f"Decoding(took {end - start:.3f} seconds)")

        print("Decrypted results for intersecting keys:", decoded_decrypted_results)
        return decoded_decrypted_results


circuit = HomomorphicPSI()

print("Circuit created, simulating computations...")

# Predefined input data
g_key = np.array(
   [
    1005, 1002, 1003, 1004, 1005, 1006, 1007, 1008,
    1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016,
    1017, 1108, 1019, 1020, 1021, 1022, 1023, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032,
    ])
given_key = np.array(
   [
    1001, 1002, 1010, 1005, 10013, 1005, 1012, 1002,
    10035, 1010, 1011, 1012, 1011, 1014, 1015, 1011,
    1017, 1001, 1019, 1020, 1042, 1022, 1023, 1044,
    1027, 1026, 1027, 1040, 1002, 1001, 1033, 1003,
    ])

def hash_value(value, base_salt="myApp_salt"):
    # Use the current date and time to create a dynamic part of the salt
    dynamic_salt = f"{base_salt}_{time.strftime('%Y%m%d%H%M%S')}"
    # Convert the integer to bytes, using the combined salt for added unpredictability
    value_bytes = f"{value}{dynamic_salt}".encode()
    hashed_bytes = hashlib.sha256(value_bytes).digest()
    # Convert the hash output to an integer for sorting
    return int.from_bytes(hashed_bytes, byteorder='big')

def reorder_based_on_hash(values):
    # Hash each value and get its original index
    hashed_values = [(hash_value(value), index) for index, value in enumerate(values)]
    # Sort based on hash values
    sorted_indices = [index for _, index in sorted(hashed_values)]
    # Reorder the original array based on the sorted indices
    return [values[i] for i in sorted_indices]

print(g_key)
print(given_key)


intersection_results = circuit.PSI(g_key, given_key)
intersection_results_hash = reorder_based_on_hash(intersection_results)


print("Final Decrypted results is:", intersection_results_hash)