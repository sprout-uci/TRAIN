module  casu_ep_per (

// OUTPUTs
    per_dout,                       // Peripheral data output
    ER_min,                          // CASU ER_min
    ER_max,                          // CASU ER_max

// INPUTs
    mclk,                           // Main system clock
    per_addr,                       // Peripheral address
    per_din,                        // Peripheral data input
    per_en,                         // Peripheral enable (high active)
    per_we,                         // Peripheral write enable (high active)
    puc_rst                         // Main system reset
);

// OUTPUTs
output      [15:0] per_dout;        // Peripheral data output
output      [15:0] ER_min;          // CASU ER_min
output      [15:0] ER_max;          // CASU ER_max

// INPUTs
input              mclk;            // Main system clock
input       [13:0] per_addr;        // Peripheral address
input       [15:0] per_din;         // Peripheral data input
input              per_en;          // Peripheral enable (high active)
input        [1:0] per_we;          // Peripheral write enable (high active)
input              puc_rst;         // Main system reset


//=============================================================================
// 1)  PARAMETER DECLARATION
//=============================================================================

// CASU's Executable Pointers consists of
//  - 16 bits of ER_min
//  - 16 bits of ER_max


// Register base address (must be aligned to decoder bit width)
parameter       [14:0] BASE_ADDR   = 15'h0140;

                                                         
// Decoder bit width (defines how many bits are considered)
parameter              DEC_WD      =  2;                 // TODO:
                                                         
// Register addresses offset                             
parameter [DEC_WD-1:0] ERMIN      =  'h0,               
                       ERMAX      =  'h1;            
                                                         
                                                         
// Register one-hot decoder utilities                    
parameter              DEC_SZ      =  (1 << DEC_WD);        
parameter [DEC_SZ-1:0] BASE_REG   =  {{DEC_SZ-1{1'b0}}, 1'b1};
                                                         
// Register one-hot decoder                              
parameter [DEC_SZ-1:0] ERMIN_D  = (BASE_REG << ERMIN), 
                       ERMAX_D  = (BASE_REG << ERMAX);
                       
//============================================================================
// 2)  REGISTER DECODER
//============================================================================

// Local register selection
wire              reg_sel      =  per_en & (per_addr[13:DEC_WD-1]==BASE_ADDR[14:DEC_WD]);

// Register local address
wire [DEC_WD-1:0] reg_addr     =  {1'b0, per_addr[DEC_WD-2:0]};

// Register address decode
wire [DEC_SZ-1:0] reg_dec      = (ERMIN_D  &  {DEC_SZ{(reg_addr==ERMIN)}}) |
                                 (ERMAX_D  &  {DEC_SZ{(reg_addr==ERMAX)}});
                                 

// Read/Write probes
wire              reg_write =  |per_we & reg_sel;
wire              reg_read  = ~|per_we & reg_sel;

// Read/Write vectors
wire [DEC_SZ-1:0] reg_wr    = reg_dec & {512{reg_write}};
wire [DEC_SZ-1:0] reg_rd    = reg_dec & {512{reg_read}};


//============================================================================
// 3) REGISTERS
//============================================================================

// ER_min Register
//-----------------
reg  [15:0] ermin;

wire       ermin_wr  = reg_wr[ERMIN];
wire [15:0] ermin_nxt = per_din;

always @ (posedge mclk or posedge puc_rst)
  if (puc_rst)        ermin <=  16'hE000;
  else if (ermin_wr)  ermin <=  ermin_nxt;
  
// ER_max Register
//-----------------
reg  [15:0] ermax;

wire       ermax_wr  = reg_wr[ERMAX];
wire [15:0] ermax_nxt = per_din;

always @ (posedge mclk or posedge puc_rst)
if (puc_rst)        ermax <=  16'hEFFF;
else if (ermax_wr) ermax <=  ermax_nxt;


//============================================================================
// 4) DATA OUTPUT GENERATION
//============================================================================

// Data output mux
wire [15:0] ermin_rd     = ermin             & {16{reg_rd[ERMIN]}};
wire [15:0] ermax_rd     = ermax             & {16{reg_rd[ERMAX]}};

wire [15:0] per_dout  =  ermin_rd  |
                         ermax_rd;
                         
wire [15:0] ER_min = ermin;
wire [15:0] ER_max = ermax;

endmodule