import time
import concrete.numpy as cnp
import numpy as np
from faker import Faker
import csv
import hashlib
import os

# Bitwidth of each chunk and number of chunks in each 32-bit number.
#index = 0
NUMBER_OF_ENTRIES = 5
WIDTH, NUM_CHUNKS = 4, 8
assert (WIDTH * NUM_CHUNKS == 32)
STATE_SHAPE = (NUMBER_OF_ENTRIES, NUM_CHUNKS)


def break_down_data(data, data_size):
    all_chunks = [
        [(x >> i * WIDTH) % (2**WIDTH) for i in range(data_size // WIDTH)[::-1]]
        for x in data
    ]
    return all_chunks

def encode(key):
    if isinstance(key, int):
        key = [key]
    encoded_key = break_down_data(key, 32)
    return encoded_key

def chunks_to_uint32(chunks):
    return int(sum([2**((NUM_CHUNKS-1-i)*WIDTH)*x for i, x in enumerate(chunks)]))

def decode(result, key_chunks):
    if result != 0:
        int_result = chunks_to_uint32(key_chunks)
        return int_result
    else:
        print(f"Intersection not happened")
        return 0


def _PSI_impl(g_chunk, given_chunk, index):
    intersect = np.sum(np.bitwise_xor(g_chunk, given_chunk) == 0) == NUM_CHUNKS
    print("Encrypted Intersection is :", intersect)
    result = intersect * index
    return result


class SimulatedCircuit:
   
    # The circuit used to implement the xor_query
    _PSI_circuit: cnp.Circuit
 
    
    
    def load_data(self, csv_file_path):
        g_keys = []
        with open(csv_file_path, 'r') as csv_file:
            
            for row in csv_file:
                snomed_codes = [int(code.strip()) for code in row.split(',')]
                g_keys.append(snomed_codes)
        return g_keys

                
    def __init__(self):
        self._state = np.zeros(STATE_SHAPE, dtype=np.int64)

        # Load the keys dataset
        self.loaded_keys = self.load_data("g_keys_dataset_AC.csv")
        csv_file_path = "g_keys_dataset_AC.csv"

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
                # key
                np.ones(NUM_CHUNKS, dtype=np.int64) * (2**WIDTH - 1) * NUMBER_OF_ENTRIES,
                # candidate_key
                np.ones(NUM_CHUNKS, dtype=np.int64) * (2**WIDTH - 1) * NUMBER_OF_ENTRIES, 
                1,
            )
        ]

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

        # Define the path for the encrypted results file
        encrypted_results_file_path = "encrypted_results.txt"

        start = time.time()
        g_key_array = np.array(g_key)
        given_key_array = np.array(given_key)

        g_key_chunks = encode(g_key_array)
        given_key_chunks = encode(given_key_array)
        end = time.time()
        print(f"Encoding (took {end - start:.3f} seconds)")

        decoded_decrypted_results = []
        index = 1  # Initialize the index

        for g_chunk, given_chunk in zip(g_key_chunks, given_key_chunks):
            reshaped_g_chunk = np.array(g_chunk).reshape(-1)
            reshaped_given_chunk = np.array(given_chunk).reshape(-1)

            start = time.time()
            encrypted_chunk = self._PSI_circuit.encrypt(reshaped_g_chunk, reshaped_given_chunk, index)
            result_chunk = self._PSI_circuit.run(encrypted_chunk)
            end = time.time()
            print(f"Encryption (took {end - start:.3f} seconds)")

            # Write the encrypted results to a file
            with open(encrypted_results_file_path, "a") as file:
                encrypted_result= result_chunk
                file.write(str(encrypted_result) + '\n')
                print(f"Encrypted results saved to {encrypted_results_file_path}")

            start = time.time()
            decrypted_result = self._PSI_circuit.decrypt(result_chunk)
            end = time.time()
            print(f"Decryption (took {end - start:.3f} seconds)")

            print("Intersection result for this pair is:", decrypted_result)

            # Decoding the result
            start = time.time()
            decoded_result = decode(decrypted_result, reshaped_given_chunk)
            if decoded_result is not None:
                decoded_decrypted_results.append(decoded_result)
            end = time.time()
            print(f"Decoding (took {end - start:.3f} seconds)")
            index += 1
            
        # Get the size of the file
        file_size = os.path.getsize(encrypted_results_file_path)

        print(f"Size of {encrypted_results_file_path}: {file_size} bytes")
        print("Decrypted results for intersecting keys:", decoded_decrypted_results)
        return decoded_decrypted_results




circuit = SimulatedCircuit()

g_keys_dataset_path = "g_keys_dataset_AC.csv"
g_keys = circuit.load_data(g_keys_dataset_path)

print("Circuit created, simulating computations...")


given_key = np.array(
   [
    1006,1007,1002,1009,1007,1004,1003,1005,
    1005,1006,1007,1001,1005,1002,1004,1004,
    1001,1002,1006,1007,1003,1005,1001,1002,
    1008,1009,1008,1006,1007,1003,1001,1010
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
for g_key_AC in g_keys:

    intersection_results = circuit.PSI(g_key_AC, given_key)


    intersection_results_hash = reorder_based_on_hash(intersection_results)

    print("Final Decrypted results without using hash is:", intersection_results)
    print("Final Decrypted results with hash is:", intersection_results_hash)

    # Specify the file path for the output
    output_file_path = "final_results.csv"

    # Open a file to write
    with open(output_file_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        # Write a header or any initial information if needed
        writer.writerow(['Decrypted Results', 'Hash-Reordered Results'])
        
        # Assuming intersection_results and intersection_results_hash are lists
        # If they are not of equal length, adjust accordingly
        for decrypted_result, hashed_result in zip(intersection_results, intersection_results_hash):
            writer.writerow([decrypted_result, hashed_result])

    print(f"Results saved to {output_file_path}")
