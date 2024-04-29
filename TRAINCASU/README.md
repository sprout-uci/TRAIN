# TRAPS: TOCTOU Resilient Attestation Protocol for Swarms of low-end embedded systems

HARDWARE CHANGES from CASU


**TRAPS/vrased/hw-mod/garota.v**          -  removed unnecessary functionality (atomicity (covered by VRASED), PMEM protection (covered by CASU), timer interrupt (not used), gpio interrupt (not used)

**TRAPS/vrased/hw-mod/hwmod.v**             - added garota_reset wire

**TRAPS/vrased/hw-mod/memory_protection.v** - SAME as garota/garota/hw-mod/memory_protection.v

**TRAPS/vrased/hw-mod/irq_disable_detect.v** - SAME as garota/garota/hw-mod/irq_disable_detect.v.v

**TRAPS/vrased/hw-mod/irq_detect.v** - SAME as garota/garota/hw-mod/irq_detect.v

**TRAPS/openmsp430/msp_core/openMSP430.v**          - added gie for interrupts
