module casu (
    clk,
    
    pc,
    
    data_wr,
    data_addr,
    
    dma_addr,
    dma_en,

    ER_min,
    ER_max,
    
    reset
);

// INPUTs and OUTPUTs
input           clk;
input   [15:0]  pc;
input           data_wr;
input   [15:0]  data_addr;
input   [15:0]  dma_addr;
input           dma_en;
input   [15:0]  ER_min;
input   [15:0]  ER_max;
output          reset;

// MACROS ///////////////////////////////////////////

parameter SMEM_BASE = 16'hA000;
parameter SMEM_SIZE = 16'h4000;

parameter SCACHE_BASE  = 16'hFFDF;
parameter SCACHE_SIZE  = 16'h0033;

parameter EP_BASE  = 16'h0140;
parameter EP_SIZE  = 16'h0003;

parameter RESET_HANDLER = 16'h0000;

//-------------States---------------------------------------
parameter RUN  = 2'b0, KILL = 2'b1;

//-------------Internal Variables---------------------------
reg             state;
reg             casu_reset;
//


initial
    begin
        state = KILL;
        casu_reset = 0;
    end

wire pc_reset = pc == RESET_HANDLER;
wire pc_in_casu = (pc >= SMEM_BASE && pc <= SMEM_BASE + SMEM_SIZE - 2);
wire pc_in_ER = (pc >= ER_min && pc <= ER_max);
wire invalid_modifications_CPU = data_wr && ((data_addr >= ER_min && data_addr <= ER_max) 
                                     || (data_addr >= SCACHE_BASE && data_addr <= SCACHE_BASE + SCACHE_SIZE - 2) 
                                     || (data_addr >= EP_BASE && data_addr <= EP_BASE + EP_SIZE - 2));
wire invalid_modifications_DMA = dma_en && ((dma_addr >= ER_min && dma_addr <= ER_max) 
                                     || (dma_addr >= SCACHE_BASE && dma_addr <= SCACHE_BASE + SCACHE_SIZE - 2) 
                                     || (dma_addr >= EP_BASE && dma_addr <= EP_BASE + EP_SIZE - 2));

// Modifications to ER is always disallowed to CPU and DMA, except when CPU is executing CASU Trusted Code
wire violation1 = (!pc_in_casu && invalid_modifications_CPU) || invalid_modifications_DMA;

// Execution of any software other than CASU Trusted Code and ER is not allowed
wire violation2 = !pc_in_casu && !pc_in_ER && !pc_reset;

wire violation = violation1 || violation2;

always @(posedge clk)
if( state == RUN && violation )
    state <= KILL;
else if (state == KILL && pc_reset && !violation)
    state <= RUN;
else state <= state;
    
always @(posedge clk)
if (state == RUN && violation )
    casu_reset <= 1'b1;
else if (state == KILL && pc_reset && !violation)
    casu_reset <= 1'b0;
else if (state == KILL)
    casu_reset <= 1'b1;
else if (state == RUN)
    casu_reset <= 1'b0;
else casu_reset <= 1'b0;
        
assign reset = casu_reset;

endmodule