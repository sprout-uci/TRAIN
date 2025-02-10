module  X_stack (
    clk,
    pc,
    data_addr,
    r_en,
    w_en,
    //pc_en,

    reset
);

input		clk;
input   [15:0]  pc;
//input		pc_en;
input   [15:0]  data_addr;
input           r_en;
input           w_en;
output          reset;

// MACROS ///////////////////////////////////////////
parameter SDATA_BASE = 16'h400;
parameter SDATA_SIZE = 16'hC00;
//
parameter HMAC_BASE = 16'h8000;
parameter HMAC_SIZE = 16'h001F;
//
parameter CTR_BASE = 16'h9000;
parameter CTR_SIZE = 16'h001F;
//
parameter SCACHE_BASE = 16'hFFDF;
parameter SCACHE_SIZE = 16'h0021;
//
parameter SMEM_BASE = 16'hA000;
parameter SMEM_SIZE = 16'h4000;
//
parameter KMEM_BASE = 16'hFEFE;
parameter KMEM_SIZE = 16'h001F;

parameter UART_BASE = 16'h0080;
parameter UART_SIZE = 16'h0010;

parameter INTR_BASE = 16'h0130;
parameter INTR_SIZE = 16'h00D0;
/////////////////////////////////////////////////////


parameter RESET_HANDLER = 16'hfffe;
parameter RUN  = 1'b0, KILL = 1'b1;
//-------------Internal Variables---------------------------
reg             state;
reg             key_res;
//

initial
    begin
        state = RUN;
        key_res = 1'b0;
    end

wire pc_not_in_srom = pc < SMEM_BASE || pc > SMEM_BASE + SMEM_SIZE -2;
wire pc_in_srom = !pc_not_in_srom;

wire daddr_not_in_sdata = data_addr < SDATA_BASE || data_addr > SDATA_BASE + SDATA_SIZE -1;
wire daddr_in_sdata = !daddr_not_in_sdata;

wire daddr_not_in_krom = data_addr < KMEM_BASE || data_addr > KMEM_BASE + KMEM_SIZE -1;
wire daddr_in_krom = !daddr_not_in_krom;

wire daddr_not_in_HMAC = data_addr < HMAC_BASE || data_addr > HMAC_BASE + HMAC_SIZE -1;
wire daddr_in_HMAC = !daddr_not_in_HMAC;

wire daddr_not_in_CTR = data_addr < CTR_BASE || data_addr > CTR_BASE + CTR_SIZE -1;
wire daddr_in_CTR = !daddr_not_in_CTR;

wire daddr_not_in_SCACHE = data_addr < SCACHE_BASE || data_addr > SCACHE_BASE + SCACHE_SIZE -1;
wire daddr_in_SCACHE = !daddr_not_in_SCACHE;

wire daddr_not_in_UART = data_addr < UART_BASE || data_addr > UART_BASE + UART_SIZE -1;
wire daddr_in_UART = !daddr_not_in_UART;

wire daddr_not_in_INTR = data_addr < INTR_BASE || data_addr > INTR_BASE + INTR_SIZE -1;
wire daddr_in_INTR = !daddr_not_in_INTR;

wire violation1 = pc_not_in_srom && daddr_in_sdata && (r_en || w_en);
wire violation2 = 0;//pc_in_srom && w_en && daddr_not_in_sdata && daddr_not_in_HMAC && daddr_not_in_CTR && daddr_not_in_SCACHE && daddr_not_in_UART && daddr_not_in_INTR;
// wire violation2 = pc_in_srom && w_en && daddr_not_in_sdata && daddr_not_in_HMAC && daddr_not_in_CTR;
wire violation3 = pc_not_in_srom && daddr_in_CTR && daddr_in_SCACHE && w_en;

// State transition logic//////
always @(posedge clk)
if(state == RUN && violation1)
    state <= KILL;
else if (state == RUN && violation2)
    state <= KILL;
else if (state == RUN && violation3)
    state <= KILL;
else if (state == KILL && (pc == RESET_HANDLER) && !violation1 && !violation2 && !violation3)
    state <= RUN;
else state <= state;
//////////////////////////////

// Output logic //////////////
always @(posedge clk)
if( 
    (state == RUN && violation1) ||
    (state == RUN && violation2) ||
    (state == RUN && violation3)
)
    key_res <= 1'b1;
else if (state == KILL && pc == RESET_HANDLER && !violation1 && !violation2 && !violation3)
    key_res <= 1'b0;
else if (state == KILL)
    key_res <= 1'b1;
else
    key_res <= 1'b0;

/////////////////////////////

assign reset = key_res;

endmodule
