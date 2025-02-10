#include <isr_compat.h>
#include <string.h>
#include "hardware.h"

#define CTR_ADDR 0xFFC0
#define VRF_AUTH 0x0250

#define MAC_ADDR 0x0230
#define KEY_ADDR 0x6A00

#define ATTEST_DATA_ADDR 0xE000
#define ATTEST_SIZE 0x1000

#define LMT_ADDR 0x0040
#define LMT_SIZE 0x0020

#define AUTH_HANDLER 0xA07E

// Communication
#define DELAY 100
#define UART_TIMEOUT 0x7FFE
#define ACK 'a'

// Watchdog timer
#define WDTCTL_ 0x0120 /* Watchdog Timer Control */
#define WDTHOLD (0x0080)
#define WDTPW (0x5A00)

// Timmer settings
#define TIMER_1MS 125
#define MAX_TIME 0xffff
#define TRAPS_TIME MAX_TIME // 50*TIMER_1MS // Time in ms -- note vivado sim is 4x faster

// TCB version // AUTOMATED: Do not edit
#define NOT_SIM 0
#define SIM 1
#define IS_SIM NOT_SIM

// Global Variables & MACROS
#define MSG_TYPE_REQ (0)
#define MSG_TYPE_REF (1)
#define MSG_TYPE_REP (2)
#define MSG_TYPE_REP_REF (3)

#define SIZE_HASH (32)

#define SIZE_SIGNATURE (32)

volatile uint32_t cur_seq = (0);
volatile uint32_t epoch_time;
volatile uint64_t count = 0;
uint8_t cur_hash[SIZE_HASH] = { // hash of BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
    0x42, 0x5E, 0xD4, 0xE4, 0xA3, 0x6B, 0x30, 0xEA, 0x21, 0xB9, 0x0E, 0x21, 0xC7, 0x12, 0xC6, 0x49,
    0xE8, 0x21, 0x4C, 0x29, 0xB7, 0xEA, 0xF6, 0x80, 0x89, 0xD1, 0x03, 0x9C, 0x6E, 0x55, 0x38, 0x4C};
volatile uint32_t cur_hash_idx = 80;
volatile uint32_t parent = 0;
volatile uint32_t dev_id = 1;

#define SIZE_KEY (32)
#define START_BYTE 0x7E
#define END_BYTE 0x7D
#define ACKTWO 'f'

struct __attribute__((__packed__)) req_msg
{
  uint8_t msg_type;
  uint32_t snd_id;
  uint8_t auth_req[SIZE_HASH];
  uint32_t seq;
  uint32_t hash_idx;
  uint8_t hash[SIZE_HASH];
  uint32_t cur_time;
};

struct __attribute__((__packed__)) att_req_msg
{
  uint8_t msg_type;
  uint32_t snd_id;
  uint32_t hash_idx;
  uint8_t hash[SIZE_HASH];
  uint32_t cur_time;
};

struct __attribute__((__packed__)) req_msg_lmt
{
  uint8_t msg_type;
  uint32_t snd_id;
  uint8_t auth_req[SIZE_HASH];
  uint32_t seq;
  uint32_t hash_idx;
  uint8_t hash[SIZE_HASH];
  uint32_t cur_time;
  uint8_t lmt[LMT_SIZE];
};

struct __attribute__((__packed__)) ref_msg
{
  uint8_t msg_type;
  uint32_t snd_id;
  uint8_t auth_ref[SIZE_HASH];
  uint32_t seq;
  uint32_t hash_idx;
  uint8_t hash[SIZE_HASH];
  uint32_t new_hash_idx;
  uint8_t new_hash[SIZE_HASH];
  uint32_t cur_time;
};

struct __attribute__((__packed__)) auth_req_hash
{
  uint8_t msg_type;
  uint8_t hash[SIZE_HASH];
  uint32_t seq;
  uint32_t hash_idx;
  uint32_t cur_time;
};

struct __attribute__((__packed__)) auth_ref_hash
{
  uint8_t msg_type;
  uint8_t hash[SIZE_HASH];
  uint32_t seq;
  uint32_t hash_idx;
  uint8_t new_hash[SIZE_HASH];
  uint32_t new_hash_idx;
  uint32_t cur_time;
};

struct __attribute__((__packed__)) auth_rep
{
  uint32_t dev_id;
  uint32_t cur_time;
  uint8_t new_hash[SIZE_HASH];
  uint8_t lmt[LMT_SIZE];
};

struct __attribute__((__packed__)) att_rep
{
  uint8_t msg_type;
  uint32_t dev_id;
  uint32_t par;
  uint32_t attesttime;
  uint8_t new_hash[SIZE_HASH];
  uint8_t lmt[LMT_SIZE];
  uint8_t auth_rep[SIZE_HASH];
};

#define RING_BUF_SIZE (256)
uint8_t rxdata[RING_BUF_SIZE];
uint8_t rx_start = 0;
uint8_t rx_end = 0;

extern void hash(uint8_t *hash1, uint8_t *input, uint32_t len);

extern void
hmac(
    uint8_t *mac,
    uint8_t *key,
    uint32_t keylen,
    uint8_t *data,
    uint32_t datalen);

void my_memset(uint8_t* ptr, int len, uint8_t val) 
{
  int i=0;
  for(i=0; i<len; i++) ptr[i] = val;
}

#pragma vector = TIMERA0_VECTOR
__interrupt __attribute__((section(".do_mac.body"))) void timer(void)
{
   __asm__ volatile("dint"
                   "\n\t");
  struct auth_rep retrieved_struct;
  struct auth_rep *ptr = (struct auth_rep *)(uintptr_t)0x5800;
  retrieved_struct = *ptr;

  uint32_t tim;
  uint32_t *timptr = (uint32_t)(uintptr_t)0x5768;
  uint32_t wait = retrieved_struct.cur_time * 6;
  tim = *timptr;
  if (tim > wait)
  {
    //    send_buf(&retrieved_struct,  sizeof(retrieved_struct));
    uint8_t key[SIZE_KEY] = {0};
    uint8_t auth_rep[SIZE_SIGNATURE] = {0};
    memset(key, 0, SIZE_KEY);
    memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY); // K
    hmac((uint8_t *)auth_rep, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)&retrieved_struct, (uint32_t)(sizeof(retrieved_struct)));

    // send_buf(&auth_rep, SIZE_HASH);

    struct att_rep att_rep;

    att_rep.msg_type = MSG_TYPE_REP;
    att_rep.dev_id = dev_id;
    att_rep.par = parent;
    att_rep.attesttime = retrieved_struct.cur_time;               
    memcpy(att_rep.new_hash, retrieved_struct.new_hash, SIZE_HASH); 
    memcpy(att_rep.lmt, retrieved_struct.lmt, SIZE_HASH); 
    memcpy(att_rep.auth_rep, auth_rep, SIZE_HASH);                 

    send_buf(&att_rep, sizeof(att_rep));

    CCTL0 &= ~CCIE;
    UART_CTL = UART_EN | UART_IEN_RX;
    epoch_time++;
    tim = 0;
  }
  else
  {
    tim++;
    uintptr_t timer_address = (uintptr_t)0x5768;
    uint32_t *timerptr = (uint32_t *)timer_address;
    *timerptr = tim;
  }
    __asm__ volatile("eint"
                   "\n\t");
  __asm__ volatile("add	#246,	r1	;#0x00f6"
                   "\n\t");
  __asm__ volatile("pop r4"
                   "\n\t");
  __asm__ volatile("pop r10"
                   "\n\t");
  __asm__ volatile("pop r11"
                   "\n\t");
  __asm__ volatile("pop r12"
                   "\n\t");
  __asm__ volatile("pop r13"
                   "\n\t");
  __asm__ volatile("pop r14"
                   "\n\t");
  __asm__ volatile("pop r15"
                   "\n\t");
  __asm__ volatile("pop r2"
                   "\n\t");
  __asm__ volatile("pop r5"
                   "\n\t");
  __asm__ volatile("br #__mac_leave"
                   "\n\t");
}


__attribute__((section(".do_mac.lib"))) inline void my_memcpy(uint8_t* dst, uint8_t* src, int size) 
{
  int i=0;
  for(i=0; i<size; i++) dst[i] = src[i];
}

int secure_memcmp(const uint8_t* s1, const uint8_t* s2, int size);


#pragma vector = UART_RX_VECTOR
__interrupt __attribute__((section(".do_mac.body"))) void uart(void)
{
   dint();
  uint8_t sendByte = ACK;
  send_buf(&sendByte, sizeof(sendByte));

  read_byte();
  P3OUT = ~P3OUT;
  TACCTL0 &= ~CCIFG;

  eint();
  //UART_STAT = UART_RX_PND;
   __asm__ volatile("incd	r1"
                   "\n\t");
  __asm__ volatile("pop r12"
                   "\n\t");
  __asm__ volatile("pop r13"
                   "\n\t");
  __asm__ volatile("pop r14"
                   "\n\t");
  __asm__ volatile("pop r15"
                   "\n\t");
  __asm__ volatile("pop r4" "\n\t");
  __asm__ volatile("pop r6" "\n\t");
  __asm__ volatile("mov r4, r2" "\n\t");
  /*__asm__ volatile("pop r2"
                   "\n\t");
  __asm__ volatile("pop r6"
                   "\n\t");*/
  __asm__ volatile( "br      #__mac_leave" "\n\t");


}

__attribute__((section(".do_mac.lib"))) void read_byte()
{
  struct req_msg req_msg;
  struct att_req_msg att_req_msg;
  uint8_t rxbyte = 0;
  uint8_t key[SIZE_KEY] = {0};
  while (rxbyte != END_BYTE)
  {
    recv_buf(&rxbyte, sizeof(rxbyte));
    P3OUT = ~P3OUT;

    if (rxbyte != END_BYTE)
    {
      rxdata[rx_end++] = rxbyte;

      if (rx_end == RING_BUF_SIZE)
      {
        rx_end = 0;
      }
    }
    send_buf(&rxbyte, sizeof(rxbyte));
  }
  //send_buf(&rx_start, sizeof(rx_start));
  //send_buf(&rx_end, sizeof(rx_end));
  //send_buf(&rxdata[0], sizeof(rx_start));
 // send_buf(&rxdata[rx_start], sizeof(rx_start));
  //send_buf(&rxdata[0], RING_BUF_SIZE);
  uint8_t sendByte = ACK;

  
  switch (rxdata[rx_start])
  {
  //send_buf(&rxdata[rx_start], sizeof(rx_start));
 // send_buf(&rxdata[0], sizeof(rx_start));

 // send_buf(&sendByte, sizeof(sendByte));
  case MSG_TYPE_REQ: // line 3
   // send_buf(&sendByte, sizeof(sendByte));
   // send_buf(&rxbyte, sizeof(rxbyte));
    if (rx_start > rx_end)
    {
      my_memcpy((uint8_t *)&att_req_msg, &rxdata[rx_start], RING_BUF_SIZE - rx_start); // line 4
      my_memcpy(((uint8_t *)&att_req_msg + RING_BUF_SIZE - rx_start), &rxdata[0], rx_end + 1);
    }
    else
    {
      my_memcpy((uint8_t *)&att_req_msg, &rxdata[rx_start], rx_end - rx_start + 1);
    }
   // send_buf((uint8_t *)&att_req_msg, sizeof(att_req_msg));
    memset(rxdata, 0, sizeof(rxdata));
    rx_start = 0;
    rx_end = 0;

    /*
    struct __attribute__((__packed__)) req_msg {
  uint8_t msg_type;     \x00
  uint32_t snd_id;      HOST
  uint8_t auth_req[SIZE_HASH]; 32 bytes \x9a\n\xc9\xd1\\\x0f\x11\xff\x8bC\xc0\x02\r\xaa\xa7\xf1\x15\xfcu\xe1r\xc5^*\xf9~\x87\x0b\xb7\xe6\x868
  uint32_t seq;   0004       \x04\x00\x00\x00
  uint32_t hash_idx; 0079   \x4F\x00\x00\x00
  uint8_t hash[SIZE_HASH]; 32 bytes BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
  uint32_t cur_time; 0009     \x09\x00\x00\x00
  };*/

    uint8_t sendF = ACKTWO;
    uint8_t sendB = 'b';
    uint8_t sendG = 'g';
    uint8_t sendH = 'h';
    uint8_t sendI = 'i';
    uint8_t sendJ = 'j';

   /* send_buf(&sendF, sizeof(sendF));
    send_buf((uint8_t *)&att_req_msg.msg_type, sizeof(uint8_t));
    send_buf(&sendF, sizeof(sendF));
    send_buf((uint8_t *)&att_req_msg.snd_id, sizeof(uint32_t));
    send_buf(&sendF, sizeof(sendF));
    send_buf((uint8_t *)&att_req_msg.auth_req, SIZE_HASH);
    send_buf(&sendF, sizeof(sendF));
    send_buf((uint8_t *)&att_req_msg.seq, sizeof(uint32_t));
    send_buf(&sendF, sizeof(sendF));
    send_buf((uint8_t *)&att_req_msg.hash_idx, sizeof(uint32_t));
    send_buf(&sendF, sizeof(sendF));
    send_buf((uint8_t *)&att_req_msg.hash, SIZE_HASH);
    send_buf(&sendF, sizeof(sendF));
    send_buf((uint8_t *)&att_req_msg.cur_time, sizeof(uint32_t));
    send_buf(&sendF, sizeof(sendF));*/

    // this is all fine up to here

    uint8_t hash_res[SIZE_HASH] = {0};

    if (cur_hash_idx > att_req_msg.hash_idx) // line 8
    {
      uint8_t input_hash[SIZE_HASH];
      memcpy(input_hash, att_req_msg.hash, SIZE_HASH);
      for (int i = 0; i < cur_hash_idx - att_req_msg.hash_idx; i++)
      {
        hash((uint8_t *)hash_res, (uint8_t *)input_hash, (uint32_t)SIZE_HASH);
        memcpy(input_hash, hash_res, SIZE_HASH);
      }
      if (secure_memcmp(hash_res, cur_hash, SIZE_HASH) != 0)
      {
        return;
      }
    }
    else
    {
      return;
    }
    memset(hash_res, 0, sizeof(hash_res));

    parent = att_req_msg.snd_id;
    cur_hash_idx = att_req_msg.hash_idx;
    memcpy(cur_hash, att_req_msg.hash, SIZE_HASH);
    att_req_msg.snd_id = dev_id;
    att_req_msg.msg_type = MSG_TYPE_REP;

    struct auth_rep auth_rep_struct;
    auth_rep_struct.dev_id = parent;
    auth_rep_struct.cur_time = att_req_msg.cur_time;
    memcpy(auth_rep_struct.new_hash, att_req_msg.hash, SIZE_HASH);
    memcpy(auth_rep_struct.lmt, (uint8_t *)LMT_ADDR, LMT_SIZE);

    uintptr_t memory_address = (uintptr_t)0x5800;
    struct auth_rep *ptr = (struct auth_rep *)memory_address;
    *ptr = auth_rep_struct;

     //enable timer interrupt
    TACTL = TASSEL_2 + ID_3 + MC_1;
    TACCR0 = TRAPS_TIME;
    uint32_t timr = 0;
    uintptr_t timer_address = (uintptr_t)0x5768;
    uint32_t *timerptr = (uint32_t *)timer_address;
    *timerptr = timr;

    CCTL0 = CCIE; 
    UART_CTL &= ~UART_IEN_RX;

    /*send_buf(&sendI, sizeof(sendI));

    memset(key, 0, SIZE_KEY);
    memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY); // K
    uint8_t auth_rep[SIZE_SIGNATURE] = {0};

    send_buf(&key, SIZE_KEY);
    send_buf(&sendI, sizeof(sendI));
    send_buf(&req_msg, sizeof(req_msg));

    struct req_msg_lmt auth_rep_struct;
    auth_rep_struct.msg_type = req_msg.msg_type;
    auth_rep_struct.snd_id = req_msg.snd_id;
    memcpy(auth_rep_struct.auth_req, req_msg.auth_req, SIZE_HASH);
    auth_rep_struct.seq = req_msg.seq;
    auth_rep_struct.hash_idx = req_msg.hash_idx;
    memcpy(auth_rep_struct.hash, req_msg.hash, SIZE_HASH);
    auth_rep_struct.cur_time = req_msg.cur_time;
    memcpy(auth_rep_struct.lmt, (uint8_t *)LMT_ADDR, LMT_SIZE);   //00000000000000000000000000000000 because nothing changed

    send_buf(&sendJ, sizeof(sendJ));
    send_buf(&auth_rep_struct, sizeof(auth_rep_struct));

    hmac((uint8_t *)auth_rep, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)&auth_rep_struct, (uint32_t)(sizeof(auth_rep_struct)));

    send_buf(&sendJ, sizeof(sendJ));
    send_buf(&auth_rep, SIZE_HASH);


    // create att_rep
    struct att_rep att_rep;
    att_rep.msg_type = MSG_TYPE_REP;
    att_rep.dev_id = dev_id;
    att_rep.par = parent;
    att_rep.seq = cur_seq;
    memcpy(att_rep.lmt, (uint8_t *)LMT_ADDR, LMT_SIZE);
    memcpy(att_rep.auth_rep, auth_rep, SIZE_HASH); // line 21
    send_buf(&att_rep, sizeof(att_rep));           // line 22*/
    break;
  case MSG_TYPE_REP:;
    struct att_rep rep_msg;
    if (rx_start > rx_end)
    {
      my_memcpy((uint8_t *)&rep_msg, &rxdata[rx_start], RING_BUF_SIZE - rx_start); // line 4
      my_memcpy(((uint8_t *)&rep_msg + RING_BUF_SIZE - rx_start), &rxdata[0], rx_end + 1);
    }
    else
    {
      my_memcpy((uint8_t *)&rep_msg, &rxdata[rx_start], rx_end - rx_start + 1);
    }
    send_buf((uint8_t *)&rep_msg, sizeof(rep_msg));
    memset(rxdata, 0, sizeof(rxdata));
    rx_start = 0;
    rx_end = 0;
   // if (rep_msg.seq == cur_seq)
    //{
     // rep_msg.par = parent;
      send_buf(&rep_msg, sizeof(rep_msg));
   // }
    break;
  default:
    break;
  }

  UART_STAT = UART_RX_PND;
}



__attribute__ ((section (".do_mac.call"))) void Hacl_HMAC_SHA2_256_hmac_entry() 
{
  uint8_t key[64] = {0};
  uint8_t verification[32] = {0};

  if (secure_memcmp((uint8_t*) MAC_ADDR, (uint8_t*) CTR_ADDR, 32) > 0) 
  {
    //Copy the key from KEY_ADDR to the key buffer.
    memcpy(key, (uint8_t*) KEY_ADDR, 64);
    hmac((uint8_t*) verification, (uint8_t*) key, (uint32_t) 64, (uint8_t*)MAC_ADDR, (uint32_t) 32);

    // Verifier Authentication before calling HMAC
    if (secure_memcmp((uint8_t*) VRF_AUTH, verification, 32) == 0) 
    {
      // Update the counter with the current authenticated challenge.
      memcpy((uint8_t*) CTR_ADDR, (uint8_t*) MAC_ADDR, 32);    
    
      // Key derivation function for rest of the computation of HMAC
      hmac((uint8_t*) key, (uint8_t*) key, (uint32_t) 64, (uint8_t*) verification, (uint32_t) 32);
      
      // HMAC on the LMT
      hmac((uint8_t*) key, (uint8_t*) key, (uint32_t) 32, (uint8_t*) LMT_ADDR, (uint32_t) LMT_SIZE);
      //hmac((uint8_t*) (MAC_ADDR), (uint8_t*) key, (uint32_t) 32, (uint8_t*) LMT_ADDR, (uint32_t) LMT_SIZE);

      // HMAC on the attestation region. Stores the result in MAC_ADDR itself.
      hmac((uint8_t*) (MAC_ADDR), (uint8_t*) key, (uint32_t) 32, (uint8_t*) ATTEST_DATA_ADDR, (uint32_t) ATTEST_SIZE);
    }
  }

  // setting the return addr:
  __asm__ volatile("mov    #0x0300,   r6" "\n\t");
  __asm__ volatile("mov    @(r6),     r6" "\n\t");

  // postamble
  __asm__ volatile("add     #96,    r1" "\n\t");
  //__asm__ volatile("pop     r11" "\n\t");
  __asm__ volatile( "br      #__mac_leave" "\n\t");
}


__attribute__ ((section (".do_mac.body"))) int secure_memcmp(const uint8_t* s1, const uint8_t* s2, int size) {
    int res = 0;
    int first = 1;
    for(int i = 0; i < size; i++) {
      if (first == 1 && s1[i] > s2[i]) {
        res = 1;
        first = 0;
      }
      else if (first == 1 && s1[i] < s2[i]) {
        res = -1;
        first = 0;
      }
    }
    return res;
}


__attribute__ ((section (".do_mac.leave"))) __attribute__((naked)) void Hacl_HMAC_SHA2_256_hmac_exit() 
{
  __asm__ volatile("br   r6" "\n\t");
}

__attribute__((section(".do_mac.body"))) void tcbsetup(void)
{
  uint32_t* wdt = (uint32_t*)(WDTCTL_);
  *wdt = WDTPW | WDTHOLD;
  UART_BAUD = BAUD;
  UART_CTL = UART_EN | UART_IEN_RX;
  __eint();
  __asm__ volatile("pop r6" "\n\t");
  __asm__ volatile( "br      #__mac_leave" "\n\t");
}

void setup()
{
  tcbsetup();
}
void VRASED (uint8_t *challenge, uint8_t *auth_chal, uint8_t *response) 
{
  //Copy input challenge to MAC_ADDR:
  my_memcpy ((uint8_t*)MAC_ADDR, challenge, 32);
  //Copy auth_chal to VRF_AUTH:
  my_memcpy ((uint8_t*)VRF_AUTH, auth_chal, 32);

  //Disable interrupts:
  __dint();

  // Save current value of r5 and r6:
  __asm__ volatile("push    r5" "\n\t");
  __asm__ volatile("push    r6" "\n\t");

  // Write return address of Hacl_HMAC_SHA2_256_hmac_entry
  // to RAM:
  __asm__ volatile("mov    #0x000e,   r6" "\n\t");
  __asm__ volatile("mov    #0x0300,   r5" "\n\t");
  __asm__ volatile("mov    r0,        @(r5)" "\n\t");
  __asm__ volatile("add    r6,        @(r5)" "\n\t");

  // Save the original value of the Stack Pointer (R1):
  __asm__ volatile("mov    r1,    r5" "\n\t");

  // Set the stack pointer to the base of the exclusive stack:
  __asm__ volatile("mov    #0x1002,     r1" "\n\t");
  
  // Call SW-Att:
  Hacl_HMAC_SHA2_256_hmac_entry();

  // Copy retrieve the original stack pointer value:
  __asm__ volatile("mov    r5,    r1" "\n\t");

  // Restore original r5,r6 values:
  __asm__ volatile("pop   r6" "\n\t");
  __asm__ volatile("pop   r5" "\n\t");

  // Enable interrupts:
  __eint();

  // Return the HMAC value to the application:
  my_memcpy(response, (uint8_t*)MAC_ADDR, 32);
}


/************ UART COMS ************/
__attribute__((section(".do_mac.lib"))) void recv_buf(uint8_t *rx_data, uint16_t size)
{
  P3OUT ^= 0x40;
  unsigned int i = 0, j;
  unsigned long time = 0;
  while (i < size && time != UART_TIMEOUT)
  {

#if IS_SIM == NOT_SIM
    // wait while rx buffer is empty         // implementation only
    while ((UART_STAT & UART_RX_PND) != UART_RX_PND && time != UART_TIMEOUT)
    {
      time++;
    }
    UART_STAT |= UART_RX_PND;
#endif

    if (time == UART_TIMEOUT)
    {
      break;
    }
    else
    {
      rx_data[i] = UART_RXD;

#if IS_SIM == NOT_SIM
      // implementation only
      for (j = 0; j < DELAY; j++)
      {
      } // wait for buffer to clear before reading next char
#endif

      i++;
    }
  }
  P3OUT ^= 0x40;
}

__attribute__((section(".do_mac.lib"))) void send_buf(uint8_t *tx_data, uint16_t size)
{

  //__asm__ volatile("dint" "\n\t");
  P3OUT ^= 0x20;
  unsigned int i, j;
  for (i = 0; i < size; i++)
  {
#if IS_SIM == NOT_SIM
    // delay until tx buffer is empty // implementation only
    while (UART_STAT & UART_TX_FULL)
      ;
#endif

    UART_TXD = tx_data[i];

#if IS_SIM == NOT_SIM
    // only implementation
    for (j = 0; j < DELAY; j++)
    {
    } // wait for buffer to clear before sending next char
#endif
  }
  P3OUT ^= 0x20;
  //__asm__ volatile("pop   r6" "\n\t");
 // __asm__ volatile( "br      #__mac_leave" "\n\t");
}