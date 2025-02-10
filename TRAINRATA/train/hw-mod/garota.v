`include "memory_protection.v"
`include "irq_detect.v"
`include "irq_disable_detect.v"

`ifdef OMSP_NO_INCLUDE
`else
`include "openMSP430_defines.v"
`endif

module garota (
    clk,
    pc,
    data_wr,
    data_addr,
    dma_addr,
    dma_en,
	irq,	//we need irq and gie
	gie,

    reset
);

input           clk;
input   [15:0]  pc;
input           data_wr;
input   [15:0]  data_addr;
input   [15:0]  dma_addr;
input           dma_en;
input           irq;
input           gie;
output          reset;

parameter RESET_HANDLER = 16'h0000;
//
parameter SMEM_BASE  = 16'hA000;	//parameter TCB_BASE = 16'hFAE0; why was it these values before?
parameter SMEM_SIZE  = 16'h4000;	//parameter TCB_SIZE = 16'h03FC; I think SMEM is correct though..
//
parameter UART_BASE = 16'h0080;
parameter UART_SIZE = 16'h0010;

parameter INTR_BASE = 16'h0130;
parameter INTR_SIZE = 16'h00D0;

// TAROT ///////////////////////

wire   uart_reset;
memory_protection #(
    .PROTECTED_BASE  (UART_BASE),
    .PROTECTED_SIZE  (UART_SIZE),
    .TCB_BASE  (SMEM_BASE),			//.TCB_BASE  (TCB_BASE),
    .TCB_SIZE  (SMEM_SIZE),			//.TCB_SIZE  (TCB_SIZE),
    .RESET_HANDLER  (RESET_HANDLER)
) interrupt_protection_uart (
    .clk        (clk),
    .pc         (pc),
    .data_addr  (data_addr),
    .w_en       (data_wr),
	.dma_addr	(dma_addr),
    .dma_en     (dma_en),

    .reset      (uart_reset) 
);

wire   timer_reset2;
memory_protection #(
    .PROTECTED_BASE  (INTR_BASE),
    .PROTECTED_SIZE  (INTR_SIZE),
    .TCB_BASE  (SMEM_BASE),
    .TCB_SIZE  (SMEM_SIZE),
    .RESET_HANDLER  (RESET_HANDLER)
) interrupt_protection_timer (
    .clk        (clk),
    .pc         (pc),
    .data_addr  (data_addr),
    .w_en       (data_wr),
	.dma_addr	(dma_addr),
    .dma_en     (dma_en),

    .reset      (timer_reset2) 
);

wire    irq_tcb;		//we need this because we need to disable interrupts
irq_detect #(
    .PROTECTED_BASE  (SMEM_BASE),
    .PROTECTED_SIZE  (SMEM_SIZE),
    .RESET_HANDLER  (RESET_HANDLER)
) irq_tcb_0 (
    .clk        (clk),
    .pc         (pc),
    .irq        (irq),
	.dma_en		(dma_en),
    .reset      (irq_tcb)
);

wire    no_irq_disable;
irq_disable_detect #(
    .TCB_BASE  (SMEM_BASE),
    .TCB_SIZE  (SMEM_SIZE),
    .RESET_HANDLER  (RESET_HANDLER)
) irq_disable_detect_0 (
    .clk        (clk),
    .pc         (pc),
   .gie        (gie),
    .reset      (no_irq_disable)
);

wire garota_rst = uart_reset | timer_reset2 | irq_tcb | no_irq_disable;
assign reset = garota_rst;  

endmodule