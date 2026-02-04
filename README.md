# MP-SPDZ Implemntation of Privacy-Preserving Local Energy Market Protocol 
This is an [MP-SPDZ](https://github.com/data61/MP-SPDZ) implementation of the Privacy-Preserving Local Energy Market Protocol described in [to be updated]. 

## Installation
```
Install the MP-SPDZ software https://github.com/data61/MP-SPDZ.
mv Preprocessing/* MP-SPDZ/ECDSA
mv Allocation/* MP-SPDZ/Programs/Source
```

## Running Market Clearance Allocation Programmes
The instructions below show how to run the Opt2_LEM_P program with three parties using the protocol of [Araki et al.](https://eprint.iacr.org/2016/768). Other allocation programmes can be run similarly.
> Note: Parameters (e.g., computation domain) are set below based on our experimentation. If you would like to set different parameters or run the programmes with different protocols, feel free to refer to the full documentation of [MP-SPDZ](https://mp-spdz.readthedocs.io/en/latest/readme.html).

1- Generate the necessary certificates and keys
```bash
Scripts/setup-ssl.sh 3
```
2- Compile the virtual machine 
```bash
make -j 8 replicated-field-party.x
```
3- local execution

For running all parties on the same machine, compile and run the program as follows:  
```bash
./compile.py -F 64 --budget 100000 Opt2_LEM_P
Scripts/rep-field.sh Opt2_LEM_P -v
```
4- For remote execution

For running parties on different machines:
1. Set the list of machine IP addresses in ```MPSPDZ/HOST.txt```
2. Redistribute the data in ```Player-Data ``` to the other machines
3. Compile and run the program:   
    ```bash
    Scripts/compile-run.py --budget 100000 -H Hosts -F 64 -E rep-field Opt2_LEM_P -v
    ```
### Online-only benchmarking
To benchmark only the online phase:

1- Add ```MY_CFLAGS = -DINSEC``` to ```CONFIG.mine```, then run ```make clean```

2- Execute the following to generate fake offline data: 
```bash
make Fake-Offline.x replicated-field-party.x
make -j 8 online
# Generate fake offline data
./Fake-Offline.x 3 -e 40,41,32,64
```
4- Redistribute the generated data in ```Player-Data``` to the other machines

5- For remote remote execution, compile and run the program on three machines as follows:
 ```bash
# Compile the program
./compile.py -F 64 --budget 100000 LEM_Opt

# Run on machine 0
./replicated-field-party.x -p 0 Opt2_LEM_P -F -h HOST_OF_PARTY_0 -pn PORT_NUMBER --verbose

# Run on machine 1
./replicated-field-party.x -p 1 Opt2_LEM_P -F -h HOST_OF_PARTY_0 -pn PORT_NUMBER --verbose

# Run on machine 2
./replicated-field-party.x -p 2 Opt2_LEM_P -F -h HOST_OF_PARTY_0 -pn PORT_NUMBER --verbose

```
For local execution, omit -h and -pn, and execute the run commands in three separate terminals.

## Running Market Clearance Preprocessing 
1- Compile the virtual machine
```bash
make -j 8 rep-ecdsa-party.x
 ```
2- For remote execution, run the following on three machines:
 ```bash
./rep-ecdsa-party.x -p 0 -h HOST_OF_PARTY_0 -pn PORT_NUMBER -N 3
./rep-ecdsa-party.x -p 1 -h HOST_OF_PARTY_0 -pn PORT_NUMBER -N 3
./rep-ecdsa-party.x -p 2 -h HOST_OF_PARTY_0 -pn PORT_NUMBER -N 3
```
For local execution, omit -h and -pn, and execute the commands in three separate terminals.
