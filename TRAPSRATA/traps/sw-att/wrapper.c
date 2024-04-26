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
  uint8_t msg_type;
  uint32_t dev_id;
  uint32_t cur_seq;
};

struct __attribute__((__packed__)) att_rep
{
  uint8_t msg_type;
  uint32_t dev_id;
  uint32_t par;
  uint32_t seq;
  uint8_t auth_rep[SIZE_HASH];
  uint8_t lmt[LMT_SIZE];
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

__attribute__((section(".do_mac.lib"))) inline void my_memcpy(uint8_t* dst, uint8_t* src, int size) 
{
  int i=0;
  for(i=0; i<size; i++) dst[i] = src[i];
}

int secure_memcmp(const uint8_t* s1, const uint8_t* s2, int size);


#pragma vector = UART_RX_VECTOR
__interrupt __attribute__((section(".do_mac.body"))) void uart(void)
{
  uint8_t sendByte = ACK;
  send_buf(&sendByte, sizeof(sendByte));

  read_byte();
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
  __asm__ volatile("pop r2"
                   "\n\t");
  __asm__ volatile("pop r6"
                   "\n\t");
  __asm__ volatile( "br      #__mac_leave" "\n\t");


}

__attribute__((section(".do_mac.lib"))) void read_byte()
{
  struct req_msg req_msg;
  uint8_t rxbyte = 0;
  uint8_t key[SIZE_KEY] = {0};

#ifdef MEASUREMENT
  uint16_t t1;
  uint8_t t1_overflow;
  uint16_t t2;
  uint8_t t2_overflow;

  uint8_t sendz = 'z';
  uint8_t sendm = 'm';


  TACTL = TACLR;
  for (int i=0; i<1000; i++);
  TACTL = TASSEL_2 + MC_1 + ID_3;
  TACCR0 = 0xFFFF;
  TAR = 0x00;

  send_buf(&TAR, 2);
#endif

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
  uint8_t sendByte = ACK;

  
  switch (rxdata[rx_start])
  {
  case MSG_TYPE_REQ:

#ifdef MEASUREMENT
    TACTL = TACLR;
    for (int i=0; i<1000; i++);
    TACTL = TASSEL_2 + MC_1 + ID_3;
    TACCR0 = 0xFFFF;
    TAR = 0x00;
#endif

    if (rx_start > rx_end)
    {
      my_memcpy((uint8_t *)&req_msg, &rxdata[rx_start], RING_BUF_SIZE - rx_start); // line 4
      my_memcpy(((uint8_t *)&req_msg + RING_BUF_SIZE - rx_start), &rxdata[0], rx_end + 1);
    }
    else
    {
      my_memcpy((uint8_t *)&req_msg, &rxdata[rx_start], rx_end - rx_start + 1);
    }
#ifdef MEASUREMENT
    // send_buf((uint8_t *)&req_msg, sizeof(req_msg));
#else
    send_buf((uint8_t *)&req_msg, sizeof(req_msg));
#endif

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

#ifdef MEASUREMENT

#else

#endif


    uint8_t hash_res[SIZE_HASH] = {0};
    if (cur_seq >= req_msg.seq)
    {
      break;
    }
    if (cur_hash_idx > req_msg.hash_idx)
    {
      uint8_t input_hash[SIZE_HASH];
      memcpy(input_hash, req_msg.hash, SIZE_HASH);
      for (int i = 0; i < cur_hash_idx - req_msg.hash_idx; i++)
      {
        hash((uint8_t *)hash_res, (uint8_t *)input_hash, (uint32_t)SIZE_HASH);
        memcpy(input_hash, hash_res, SIZE_HASH);
      }
      if (secure_memcmp(hash_res, cur_hash, SIZE_HASH) != 0)
      {
        break;
      }
    }
    memset(hash_res, 0, sizeof(hash_res));

    struct auth_req_hash auth_req_hash;
    auth_req_hash.msg_type = req_msg.msg_type;
    memcpy(auth_req_hash.hash, req_msg.hash, SIZE_HASH);
    auth_req_hash.seq = req_msg.seq;
    auth_req_hash.hash_idx = req_msg.hash_idx;
    auth_req_hash.cur_time = req_msg.cur_time;

#ifdef MEASUREMENT
    // send_buf(&sendF, sizeof(sendF));
    // send_buf(&auth_req_hash, sizeof(auth_req_hash));
#else
    send_buf(&auth_req_hash, sizeof(auth_req_hash));
#endif
    hash((uint8_t *)hash_res, (uint8_t *)&auth_req_hash, (uint32_t)sizeof(auth_req_hash));

#ifdef MEASUREMENT
    // send_buf(&sendG, sizeof(sendG));
    // send_buf(&hash_res, SIZE_HASH); // set the value of this to the auth_req on the python
#else
    send_buf(&hash_res, SIZE_HASH); // set the value of this to the auth_req on the python
#endif

    if (secure_memcmp(hash_res, req_msg.auth_req, SIZE_HASH))

    {
#ifdef MEASUREMENT
      // send_buf(&sendH, sizeof(sendH));
#else
#endif
      break;
    }

#ifdef MEASUREMENT
    t1 = TAR;
    t1_overflow = TACTL & TAIFG;

    TACTL = TACLR;
    for (int i=0; i<1000; i++);
    TACTL = TASSEL_2 + MC_1 + ID_3;
    TACCR0 = 0xFFFF;
    TAR = 0x00;
#endif

    cur_seq = req_msg.seq; // line 14
    parent = req_msg.snd_id;
    cur_hash_idx = req_msg.hash_idx;
    memcpy(cur_hash, req_msg.hash, SIZE_HASH);
    req_msg.snd_id = dev_id;
    req_msg.msg_type = MSG_TYPE_REP;


#ifdef MEASUREMENT
    // send_buf(&sendI, sizeof(sendI));
#else
#endif

    memset(key, 0, SIZE_KEY);
    memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY); // K
    uint8_t auth_rep[SIZE_SIGNATURE] = {0};

#ifdef MEASUREMENT
    // send_buf(&key, SIZE_KEY);
    // send_buf(&sendI, sizeof(sendI));
    // send_buf(&req_msg, sizeof(req_msg));
#else
    send_buf(&key, SIZE_KEY);
    send_buf(&req_msg, sizeof(req_msg));
#endif

    struct req_msg_lmt auth_rep_struct;
    auth_rep_struct.msg_type = req_msg.msg_type;
    auth_rep_struct.snd_id = req_msg.snd_id;
    memcpy(auth_rep_struct.auth_req, req_msg.auth_req, SIZE_HASH);
    auth_rep_struct.seq = req_msg.seq;
    auth_rep_struct.hash_idx = req_msg.hash_idx;
    memcpy(auth_rep_struct.hash, req_msg.hash, SIZE_HASH);
    auth_rep_struct.cur_time = req_msg.cur_time;
    memcpy(auth_rep_struct.lmt, (uint8_t *)LMT_ADDR, LMT_SIZE);   //00000000000000000000000000000000 because nothing changed

#ifdef MEASUREMENT
    // send_buf(&sendJ, sizeof(sendJ));
    // send_buf(&auth_rep_struct, sizeof(auth_rep_struct));
#else
    send_buf(&auth_rep_struct, sizeof(auth_rep_struct));
#endif

    hmac((uint8_t *)auth_rep, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)&auth_rep_struct, (uint32_t)(sizeof(auth_rep_struct)));

#ifdef MEASUREMENT
    // send_buf(&sendJ, sizeof(sendJ));
    // send_buf(&auth_rep, SIZE_HASH);
#else
    send_buf(&auth_rep, SIZE_HASH);
#endif


    // create att_rep
    struct att_rep att_rep;
    att_rep.msg_type = MSG_TYPE_REP;
    att_rep.dev_id = dev_id;
    att_rep.par = parent;
    att_rep.seq = cur_seq;
    memcpy(att_rep.lmt, (uint8_t *)LMT_ADDR, LMT_SIZE);
    memcpy(att_rep.auth_rep, auth_rep, SIZE_HASH); // line 21

#ifdef MEASUREMENT
    t2 = TAR;
    t2_overflow = TACTL & TAIFG;

    if (t1_overflow) {
      for (int z=0; z<4; z++) {send_buf(&sendz, sizeof(sendz));}
    } else {
      for (int z=0; z<8; z++) {send_buf(&sendm, sizeof(sendm));}
    }
    send_buf(&t1, sizeof(t1));

    if (t2_overflow) {
      for (int z=0; z<5; z++) {send_buf(&sendz, sizeof(sendz));}
    } else {
      for (int z=0; z<9; z++) {send_buf(&sendm, sizeof(sendm));}
    }
    send_buf(&t2, sizeof(t2));
#endif

    send_buf(&att_rep, sizeof(att_rep));           // line 22
    break;

  case MSG_TYPE_REF:;
    /* code */
    struct ref_msg ref_msg;
    if (rx_start > rx_end)
    {
      my_memcpy((uint8_t *)&ref_msg, &rxdata[rx_start], RING_BUF_SIZE - rx_start); // line 4
      my_memcpy(((uint8_t *)&ref_msg + RING_BUF_SIZE - rx_start), &rxdata[0], rx_end + 1);
    }
    else
    {
      my_memcpy((uint8_t *)&ref_msg, &rxdata[rx_start], rx_end - rx_start + 1);
    }
    send_buf((uint8_t *)&ref_msg, sizeof(ref_msg));
    memset(rxdata, 0, sizeof(rxdata));
    rx_start = 0;
    rx_end = 0;
    if (cur_seq >= ref_msg.seq)
    {
      break;
    }
    if (cur_hash_idx > ref_msg.hash_idx)
    {
      uint8_t input_hash[SIZE_HASH];
      memcpy(input_hash, ref_msg.hash, SIZE_HASH);
      for (int i = 0; i < cur_hash_idx - ref_msg.hash_idx; i++)
      {
        hash((uint8_t *)hash_res, (uint8_t *)input_hash, (uint32_t)SIZE_HASH);
        memcpy(input_hash, hash_res, SIZE_HASH);
      }
      if (secure_memcmp(hash_res, cur_hash, SIZE_HASH) != 0)
      {
        break;
      }
    }
    memset(hash_res, 0, sizeof(hash_res));
    struct auth_ref_hash auth_ref_hash;
    auth_ref_hash.msg_type = ref_msg.msg_type;
    memcpy(auth_ref_hash.hash, ref_msg.hash, SIZE_HASH);
    auth_ref_hash.seq = ref_msg.seq;
    auth_ref_hash.hash_idx = ref_msg.hash_idx;
    auth_ref_hash.cur_time = ref_msg.cur_time;
    auth_ref_hash.new_hash_idx = ref_msg.new_hash_idx;
    memcpy(auth_ref_hash.new_hash, ref_msg.new_hash, SIZE_HASH);
    hash((uint8_t *)hash_res, (uint8_t *)&auth_ref_hash, (uint32_t)sizeof(auth_ref_hash));
    if (secure_memcmp(hash_res, ref_msg.auth_ref, SIZE_HASH))
    {
      break;
    }


    cur_seq = ref_msg.seq;
    parent = ref_msg.snd_id;
    cur_hash_idx = ref_msg.new_hash_idx;
    memcpy(cur_hash, ref_msg.new_hash, SIZE_HASH);
    req_msg.snd_id = dev_id;
    req_msg.msg_type = MSG_TYPE_REP_REF;

    memset(key, 0, SIZE_KEY);
    memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY); // K
    uint8_t auth_rep_refresh[SIZE_SIGNATURE] = {0};

    struct req_msg_lmt auth_rep_ref_struct;
    auth_rep_ref_struct.msg_type = req_msg.msg_type;
    auth_rep_ref_struct.snd_id = req_msg.snd_id;
    memcpy(auth_rep_ref_struct.auth_req, req_msg.auth_req, SIZE_HASH);
    auth_rep_ref_struct.seq = req_msg.seq;
    auth_rep_ref_struct.hash_idx = req_msg.hash_idx;
    memcpy(auth_rep_ref_struct.hash, req_msg.hash, SIZE_HASH);
    auth_rep_ref_struct.cur_time = req_msg.cur_time;
    memcpy(auth_rep_ref_struct.lmt, (uint8_t *)LMT_ADDR, LMT_SIZE);   
    hmac((uint8_t *)auth_rep, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)&auth_rep_ref_struct, (uint32_t)(sizeof(auth_rep_ref_struct)));

    // create att_rep
    struct att_rep att_rep_ref;
    att_rep_ref.msg_type = MSG_TYPE_REP;
    att_rep_ref.dev_id = dev_id;
    att_rep_ref.par = parent;
    att_rep_ref.seq = cur_seq;
    memcpy(att_rep_ref.lmt, (uint8_t *)LMT_ADDR, LMT_SIZE);
    memcpy(att_rep_ref.auth_rep, auth_rep, SIZE_HASH); // line 21
    send_buf(&att_rep_ref, sizeof(att_rep_ref));           // line 22
    break;

  case MSG_TYPE_REP:;
    // if rep continue to rep_refresh (they're identical)
  case MSG_TYPE_REP_REF:;
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
    if (rep_msg.seq == cur_seq)
    {
      rep_msg.par = parent;
      send_buf(&rep_msg, sizeof(rep_msg));
    }
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
