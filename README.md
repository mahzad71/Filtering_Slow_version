This repository contains four Python scripts implemented to compute the Private Set Intersection (PSI) of SNOMED codes for various use cases. Employing different methods for input handling, these scripts demonstrate varied performance levels, categorized into fast and slow versions of PSI computation.

Scripts Overview
1. Fast Version - example_MMZ.py

	Functionality: Directly reads two arrays of SNOMED codes (g_keys and given_keys, each containing 32 codes) from the script and computes PSI for each corresponding pair.

	Performance: This script is fast, completing PSI computations in less than one second per pair.
   
2. Slow Version1 - Input_Not_From_File.py
   
	Functionality: Processes an array of arrays, with each sub-array representing SNOMED codes from a patient's document. These arrays are read sequentially and passed to the 		PSI function, which compares each pair to a given key and returns the PSI results in encrypted form for each pair.

	Performance: Despite a similar comparison process to the fast version, this script is significantly slower, especially during the encryption of PSI results, taking 			approximately 1 minute per pair. This slowdown is attributed to the encryption process, hence its classification as a slow version.

3. Slow Version2 - AC_xor.py (Reading from CSV)

Functionality: Inputs are sourced from a CSV file (g_keys_dataset_AC.csv), where each row includes SNOMED codes for different patients. Similar to the second script, each row is compared against a given key for PSI computation.This approach underscores PSI computation with input from external files, aligning with the methodology of the first and second scripts.

Performance: The primary difference from the second script lies in reading inputs from a file. However, the performance impact is similar, with PSI computations and encryption taking around 1 minute per pair, and we categorizing it as slow.

Final Results and Data Privacy

The final results from all scripts are displayed as 0 if no intersection is found between the SNOMED codes on that pair in two arrays (given_key and g_key). If an intersection occurs, the result is decrypted and decoded back to the intersecting SNOMED code of that pair. Importantly, all scripts incorporate a final hashing step for the PSI results, reordering them to prevent any inference of additional information.
