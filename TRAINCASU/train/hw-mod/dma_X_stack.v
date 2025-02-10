
module  dma_X_stack (
    clk,
    pc,
    dma_addr,
    dma_en,

    reset,
);

input           clk;
input   [15:0]  pc;
input   [15:0]  dma_addr;
input           dma_en;
output          reset;

// MACROS ///////////////////////////////////////////
parameter SDATA_BASE = 16'hA000;
parameter SDATA_SIZE = 16'h1000;
//
parameter SCACHE_BASE = 16'hFFDF;
parameter SCACHE_SIZE = 16'h0021;
//
parameter CTR_BASE = 16'h9000;
parameter CTR_SIZE = 16'h001F;
//
parameter UART_BASE = 16'h0080;
parameter UART_SIZE = 16'h0010;

parameter INTR_BASE = 16'h0130;
parameter INTR_SIZE = 16'h00D0;
/////////////////////////////////////////////////////

parameter RESET_HANDLER = 16'h0000;
parameter RUN  = 1'b0, KILL = 1'b1;
//-------------Internal Variables---------------------------
reg             state;
reg             key_res;
//

initial
    begin
        state = KILL;
        key_res = 1'b1;
    end

wire invalid_access_x_stack = (dma_addr >= SDATA_BASE && dma_addr < SDATA_BASE + SDATA_SIZE) && dma_en;
wire invalid_write_ctr = (dma_addr >= CTR_BASE && dma_addr < CTR_BASE + CTR_SIZE) && dma_en;
wire invalid_write_SCACHE = (dma_addr >= SCACHE_BASE && dma_addr < SCACHE_BASE + SCACHE_SIZE) && dma_en;
wire invalid_write_UART = (dma_addr >= UART_BASE && dma_addr < UART_BASE + UART_SIZE) && dma_en;
wire invalid_write_INTR = (dma_addr >= INTR_BASE && dma_addr < INTR_BASE + INTR_SIZE) && dma_en;
wire violation = invalid_access_x_stack | invalid_write_ctr | invalid_write_SCACHE | invalid_write_UART | invalid_write_INTR;

always @(posedge clk) 
if( state == RUN && violation )
    state <= KILL;
else if (state == KILL && pc == RESET_HANDLER && !violation)
    state <= RUN;
else state <= state;

always @(posedge clk)
if (state == RUN && violation )
    key_res <= 1'b1;
else if (state == KILL && pc == RESET_HANDLER && !violation)
    key_res <= 1'b0;
else if (state == KILL)
    key_res <= 1'b1;
else if (state == RUN)
    key_res <= 1'b0;
else key_res <= 1'b0;

assign reset = key_res;

endmodule
