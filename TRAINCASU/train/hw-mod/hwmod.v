`include "vrased.v"	
`include "casu.v"	
`include "garota.v"	


`ifdef OMSP_NO_INCLUDE
`else
`include "openMSP430_defines.v"
`endif

module hwmod (
    clk,
    pc,

    data_en,
    data_wr,
    data_addr,

    dma_addr,
    dma_en,

    ER_min,
    ER_max,

    irq,
	gie,
    
    reset
);


//////////// INPUTS AND OUTPUTS ////////////////////////////////

input           clk;
input   [15:0]  pc;
input           data_en;
input           data_wr;
input   [15:0]  data_addr;
input   [15:0]  dma_addr;
input           dma_en;
input   [15:0]  ER_min;
input   [15:0]  ER_max;
input           irq;
input           gie;

output          reset;


//////////// MACROS ///////////////////////////////////////////

parameter SDATA_BASE = 16'h400;
parameter SDATA_SIZE = 16'hC00;

parameter SMEM_BASE = 16'hA000;
parameter SMEM_SIZE = 16'h4000;

parameter KMEM_BASE = 16'h6A00;
parameter KMEM_SIZE = 16'h0040;

parameter SCACHE_BASE  = 16'hFFDF;
parameter SCACHE_SIZE  = 16'h0021;

parameter EP_BASE = 16'h0140;
parameter EP_SIZE = 16'h0004;

parameter HMAC_BASE = 16'h03D0;
parameter HMAC_SIZE = 16'h0020;

parameter UART_BASE = 16'h0080;
parameter UART_SIZE = 16'h0010;

parameter RESET_HANDLER = 16'h0000;


//////////// DIGITAL LOGIC /////////////////////////////////////

wire vrased_reset;

vrased #(
        .SMEM_BASE (SMEM_BASE),
        .SMEM_SIZE (SMEM_SIZE),
        .SDATA_BASE (SDATA_BASE),
        .SDATA_SIZE (SDATA_SIZE),
        .HMAC_BASE (HMAC_BASE),
        .HMAC_SIZE (HMAC_SIZE),
        .KMEM_BASE (KMEM_BASE),
        .KMEM_SIZE (KMEM_SIZE),
        .CTR_BASE  (EP_BASE),
        .CTR_SIZE  (EP_SIZE),
        .SCACHE_BASE  (SCACHE_BASE),
        .SCACHE_SIZE  (SCACHE_SIZE),
        .RESET_HANDLER (RESET_HANDLER)
) vrased_0 (
    .clk        (clk),
    .pc         (pc),
    .data_en    (data_en),
    .data_wr    (data_wr),
    .data_addr  (data_addr),
    .dma_addr   (dma_addr),
    .dma_en     (dma_en),
    .irq        (irq),
    
    .reset      (vrased_reset)
);



wire casu_reset;

casu #(
        .SMEM_BASE (SMEM_BASE),
        .SMEM_SIZE (SMEM_SIZE),
        .SCACHE_BASE (SCACHE_BASE),
        .SCACHE_SIZE (SCACHE_SIZE),
        .EP_BASE (EP_BASE),
        .EP_SIZE (EP_SIZE),
        .RESET_HANDLER (RESET_HANDLER)
) casu_0 (
    .clk        (clk),

    .pc         (pc),

    .data_wr    (data_wr),
    .data_addr  (data_addr),
    
    .dma_addr   (dma_addr),
    .dma_en     (dma_en),

    .ER_min     (ER_min),
    .ER_max     (ER_max),
    
    .reset      (casu_reset)

);


wire garota_reset;

garota #(
        .SMEM_BASE (SMEM_BASE),
        .SMEM_SIZE (SMEM_SIZE),
        .UART_BASE (UART_BASE),
        .UART_SIZE (UART_SIZE),
        .RESET_HANDLER (RESET_HANDLER)
) garota_0 (
    .clk        (clk),
    .pc         (pc),
    .data_wr    (data_wr),
    .data_addr  (data_addr),
    .dma_addr   (dma_addr),
    .dma_en     (dma_en),
	.irq        (irq),
	.gie        (gie),	//for disabling interrupts

    
    .reset      (garota_reset)
);



assign reset = vrased_reset | casu_reset | garota_reset;

endmodule