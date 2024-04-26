# TRAPS: TOCTOU Resilient Attestation Protocol for Swarms of low-end embedded systems

### TRAPS Directory Structure

    TRAPSCASU
    ├── application
    │   └── simulation
    ├── ILA_SETUP
    ├── msp_bin
    ├── openmsp430
    │   ├── contraints_fpga
    │   ├── fpga
    │   ├── msp_core
    │   ├── msp_memory
    │   ├── msp_periph
    │   └── simulation
    ├── scripts
    │   ├── build
    │   └── verif-tools
    ├── traps
    │   ├── hw-mod
    │   └── sw-att
    │       └── hacl-c
    └── utils

    TRAPSRATA
    ├── application
    │   └── simulation
    ├── msp_bin
    ├── openmsp430
    │   ├── contraints_fpga
    │   ├── fpga
    │   ├── msp_core
    │   ├── msp_memory
    │   ├── msp_periph
    │   └── simulation
    ├── scripts
    │   ├── build
    │   └── verif-tools
    ├── traps
    │   ├── hw-mod
    │   └── sw-att
    │       └── hacl-c
    └── utils


## Dependencies

Environment (processor and OS) used for development:
CPU: 13th Gen Intel i5-13600KF (20) @ 5.100GHz
OS: Kubuntu 22.04.4 LTS x86_64 
Kernel: 6.5.0-27-generic
GPU: NVIDIA GeForce RTX 3070 Ti
Memory: 64105MiB DDR5 @ 6400MHz

Dependencies on Ubuntu:

		sudo apt-get install bison pkg-config gawk clang flex gcc-msp430 iverilog
		cd scripts && make install

## Building TRAPS Software
To generate the Microcontroller program memory configuration containing TRAPS trusted software (SW-Att) and sample application (in application/main.c) code run:

        cd scripts
        make mem

To clean the built files run:

        make clean

As a result of the build, two files pmem.mem and smem.mem should be created inside msp_bin directory:

- pmem.mem program memory contents corresponding the application binaries

- smem.mem contains SW-Att binaries.

        Note: Latest Build tested using msp430-gcc (GCC) 4.6.3 2012-03-01 (mspgcc LTS 20120406 unpatched)

## Running TRAPS Prototype on FPGA

This is an example of how to Synthesize and prototype TRAPS using Basys3 FPGA and XILINX Vivado v2023.1 (64-bit) for Linux

- Vivado is available to download at: https://www.xilinx.com/support/download.html

- Basys3 Reference/Documentation is available at: https://reference.digilentinc.com/basys3/refmanual

#### Creating a Vivado Project for TRAPS

1- Clone this repository;

2 - Follow the steps in "Building TRAPS Software" (above) to generate .mem files

2- Start Vivado. On the upper left select: File -> New Project

3- Follow the wizard, select a project name and location . In project type, select RTL Project and click Next.

4- In the "Add Sources" window, select Add Files and add all *.v and *.mem files contained in the following directories of this reposiroty:

        openmsp430/fpga
        openmsp430/msp_core
        openmsp430/msp_memory
        openmsp430/msp_periph
        /vrased/hw-mod
        /msp_bin

and select Next.

5- In the "Add Constraints" window, select add files and add the file

        openmsp430/contraints_fpga/Basys-3-Master.xdc

and select Next.

        Note: this file needs to be modified accordingly if you are running TRAPS in a different FPGA.

6- In the "Default Part" window select "Boards", search for Basys3, select it, and click Next.

        Note: if you don't see Basys3 as an option you may need to download Basys3 to Vivado.

7- Select "Finish". This will conclude the creation of a Vivado Project for TRAPS.

Now we need to configure the project for systhesis.

8- In the PROJECT MANAGER "Sources" window, search for openMSP430_fpga (openMSP430_fpga.v) file, right click it and select "Set as Top".
This will make openMSP430_fpga.v the top module in the project hierarchy. Now it's name should apear in bold letters.

9- In the same "Sources" window, search for openMSP430_defines.v file, right click it and select Set File Type and, from the dropdown menu select "Verilog Header".

Now we are ready to synthesize openmsp430 with TRAPS's hardware the following steps might take several minutes.

10- On the left menu of the PROJECT MANAGER click "Run Synthesis", select execution parameters (e.g, number of CPUs used for synthesis) according to your PC's capabilities.

11- If synthesis succeeds, you will be prompted with the next step. Select "Run Implementation" and wait a few more minutes (tipically ~3-10 minutes).

12- If implementation succeeds select "Generate Bitstream" in the following window. This will generate the configuration binary to step up the FPGA according to TRAPS hardware and software.

13- After the bitstream is generated, select "Open Hardware Manager", connect the FPGA to you computers USB port and click "Auto-Connect".
Your FPGA should be now displayed on the hardware manager menu.

        Note: if you don't see your FPGA after auto-connect you might need to download Basys3 drivers to your computer.

14- Right-click your FPGA and select "Program Device" to program the FPGA.
