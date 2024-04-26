#include <isr_compat.h>
#include <stdio.h>
#include "hardware.h"
#include <stdlib.h>

// Watchdog timer
#define WDTCTL_ 0x0120 /* Watchdog Timer Control */
#define WDTHOLD (0x0080)
#define WDTPW (0x5A00)

// Timmer settings
#define TIMER_1MS 125
#define MAX_TIME 0xffff
#define TRAPS_TIME MAX_TIME // 50*TIMER_1MS // Time in ms -- note vivado sim is 4x faster

// Communication
#define DELAY 100
#define UART_TIMEOUT 0x7FFE
#define ACK 'a'
#define ACKTWO 'f'

#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))

#define FIRST 50

// TCB version // AUTOMATED: Do not edit
#define NOT_SIM 0
#define SIM 1
#define IS_SIM NOT_SIM

#include <string.h>
// #include <cstdint>

#define SIG_TEMP (0x6000)

// TODO: SIG_RESP_ADDR should be modified
#define SIG_RESP_ADDR (0x03D0)

#define KEY_ADDR (0x6A00)

#define ATTEST_DATA_ADDR (0xE000)
#define ATTEST_SIZE (0x2000)

#define SCACHE_FLAG (0xFFDF)
#define SCACHE_IVT (0xFFE0)

#define EP_START (0x0140)
#define EP_END (0x0142)
#define B_EP_START (0xFFDA)
#define B_EP_END (0xFFDC)

#define SIZE_SW_SIZE (2)
#define SIZE_VER_INFO (2)
#define SIZE_NONCE (32)
#define SIZE_IVT (32)
#define SIZE_SIGNATURE (32)
#define SIZE_HASH (32)

#define ER_FIRST_SW_START (0xE000)
#define ER_SECOND_SW_START (0xF000)
#define OFFSET_SW_SIZE (0)
#define OFFSET_VER_INFO (OFFSET_SW_SIZE + SIZE_SW_SIZE)
#define OFFSET_NONCE (OFFSET_VER_INFO + SIZE_VER_INFO)

#define SIZE_HEADER (OFFSET_NONCE + SIZE_NONCE)
#define SIZE_KEY (32)

// Define Frame Constants
#define START_BYTE 0x7E
#define END_BYTE 0x7D
#define FRAME_OVERHEAD 2 // Start byte (1), Length (1 byte),

/* TODO: Work around for the version information of existing software */
#define EXISTING_SW_VERSION (0xFFD8)

extern void hash(uint8_t *hash1, uint8_t *input, uint32_t len);

extern void
hmac(
    uint8_t *mac,
    uint8_t *key,
    uint32_t keylen,
    uint8_t *data,
    uint32_t datalen);

__attribute__((section(".do_mac.lib"))) inline void my_memcpy(uint8_t *dst, uint8_t *src, int size)
{
  for (int i = 0; i < size; i++)
    dst[i] = src[i];
}

// CASU function signatures
void tcb_entry();
void CASU_update_authenticate();
void CASU_update_install();
void CASU_jump_to_ER_routine();
void CASU_exit();
void CASU_jump_to_ER_routine_init();
int secure_memcmp(const uint8_t *s1, const uint8_t *s2, int size);
void recv_buf(uint8_t *rx_data, uint16_t size);
void send_buf(uint8_t *tx_data, uint16_t size);
void read_byte();

// Global Variables & MACROS
#define MSG_TYPE_REQ (0)
#define MSG_TYPE_REF (1)
#define MSG_TYPE_REP (2)
#define MSG_TYPE_REP_REF (3)

volatile uint32_t cur_seq = (0);
volatile uint32_t epoch_time;
volatile uint64_t count = 0;
uint8_t cur_hash[SIZE_HASH] = { // hash of BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
    0x42, 0x5E, 0xD4, 0xE4, 0xA3, 0x6B, 0x30, 0xEA, 0x21, 0xB9, 0x0E, 0x21, 0xC7, 0x12, 0xC6, 0x49,
    0xE8, 0x21, 0x4C, 0x29, 0xB7, 0xEA, 0xF6, 0x80, 0x89, 0xD1, 0x03, 0x9C, 0x6E, 0x55, 0x38, 0x4C};
volatile uint32_t cur_hash_idx = 80;
volatile uint32_t parent = 0;
volatile uint32_t dev_id = 1;
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
};

/* time sync function */
__attribute__((section(".do_mac.lib"))) void time_sync()
{
  uint8_t readyByte = 0;
  uint8_t sendByte = ACKTWO;
  send_buf(&sendByte, sizeof(sendByte));
  while (readyByte != ACK)
  {

    send_buf(&sendByte, sizeof(sendByte));
    recv_buf(&readyByte, sizeof(readyByte));
  }

  recv_buf(&epoch_time, sizeof(epoch_time));
  send_buf(&epoch_time, sizeof(epoch_time));

  return;
}

#define RING_BUF_SIZE (256)
uint8_t rxdata[RING_BUF_SIZE];
uint8_t rx_start = 0;
uint8_t rx_end = 0;

// REQ MSG: 0 ||  Snd  || Auth_req ||  Seq || HashIdx || Hash || Time
//       (1byte) (4byte)  (4byte)    (4byte)  (4byte)  (32byte)  (4byte)
__attribute__((section(".do_mac.call"))) void tcb_entry()
{

  /********** SETUP ON ENTRY **********/

  __asm__ volatile("mov    #0x1000,     r1"
                   "\n\t");
  __asm__ volatile("dint"
                   "\n\t");

  if (*(uint8_t *)SCACHE_FLAG != 0)
  {
    CASU_update_install();
  }

  __asm__ volatile("cmp.w #1, r4"
                   "\n\t");
  __asm__ volatile("jeq    CASU_update_authenticate"
                   "\n\t");

  uint32_t *wdt = (uint32_t *)(WDTCTL_);
  *wdt = WDTPW | WDTHOLD;

  // Init UART
  UART_BAUD = BAUD;
  UART_CTL = UART_EN; // SMCLK, contmode

  P3DIR = 0xFF;
  P3OUT = 0xFF;

  time_sync();

  UART_CTL = UART_EN | UART_IEN_RX;

  __asm__ volatile("jmp    CASU_jump_to_ER_routine_init"
                   "\n\t");
}

#pragma vector = UART_RX_VECTOR
__interrupt __attribute__((section(".do_mac.body"))) void uart(void)
{
  uint8_t sendByte = ACK;
  send_buf(&sendByte, sizeof(sendByte));

  read_byte();
  P3OUT = ~P3OUT;

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
  __asm__ volatile("pop r5"
                   "\n\t");
  __asm__ volatile("br      #__mac_leave"
                   "\n\t");
}

__attribute__((section(".do_mac.lib"))) void read_byte()
{
  struct req_msg req_msg;
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
  switch (rxdata[rx_start])
  {
  case MSG_TYPE_REQ:
    if (rx_start > rx_end)
    {
      my_memcpy((uint8_t *)&req_msg, &rxdata[rx_start], RING_BUF_SIZE - rx_start);
      my_memcpy(((uint8_t *)&req_msg + RING_BUF_SIZE - rx_start), &rxdata[0], rx_end + 1);
    }
    else
    {
      my_memcpy((uint8_t *)&req_msg, &rxdata[rx_start], rx_end - rx_start + 1);
    }
    send_buf((uint8_t *)&req_msg, sizeof(req_msg));
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

    // hash_res is the heartbeat.
    hash((uint8_t *)hash_res, (uint8_t *)&auth_req_hash, (uint32_t)sizeof(auth_req_hash));

    if (secure_memcmp(hash_res, req_msg.auth_req, SIZE_HASH))

    {
      send_buf(&sendH, sizeof(sendH));
      break;
    }

    cur_seq = req_msg.seq;
    parent = req_msg.snd_id;
    cur_hash_idx = req_msg.hash_idx;
    memcpy(cur_hash, req_msg.hash, SIZE_HASH);
    req_msg.snd_id = dev_id;
    req_msg.msg_type = MSG_TYPE_REP;

    uint32_t delay_cycles;
    uint32_t req_time;
    uint16_t taccr0_high, taccr0_low;


    req_time = req_msg.cur_time;
    TACTL = TASSEL_2 + MC_1 + ID_3;
    delay_cycles = (uint32_t)req_time * 137500UL;
    // Check for timer overflow
    taccr0_high = (uint16_t)(delay_cycles >> 16);
    taccr0_low = (uint16_t)(delay_cycles & 0xFFFF);

    if (taccr0_high > 0) {
        while (req_time > 0) {
            if (req_time >= 65536) {
                TACCR0 = 0xFFFF;
                req_time -= 65536;
            } else {
                TACCR0 = (uint16_t)((uint32_t)req_time * 137500UL);
                req_time = 0;
            }
            TAR = 0x00;
            while ((TACCR0 - TAR) != 0) {
              // send_buf(&sendF, sizeof(sendF));
            }
        }
    } else {
        TACCR0 = taccr0_low;
        TAR = 0x00;
        while ((TACCR0 - TAR) != 0) {
           // send_buf(&sendF, sizeof(sendF));
        }
    }

    memset(key, 0, SIZE_KEY);
    memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY);
    uint8_t auth_rep[SIZE_SIGNATURE] = {0};

    hmac((uint8_t *)auth_rep, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)&req_msg, (uint32_t)(sizeof(req_msg)));

    // create att_rep
    struct att_rep att_rep;
    att_rep.msg_type = MSG_TYPE_REP;
    att_rep.dev_id = dev_id;
    att_rep.par = parent;
    att_rep.seq = cur_seq;
    memcpy(att_rep.auth_rep, auth_rep, SIZE_HASH);
    send_buf(&att_rep, sizeof(att_rep));
    break;

  case MSG_TYPE_REF:;
    struct ref_msg ref_msg;
    if (rx_start > rx_end)
    {
      my_memcpy((uint8_t *)&ref_msg, &rxdata[rx_start], RING_BUF_SIZE - rx_start);
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


    uint32_t delay_cycle;
    uint32_t timer;
    uint16_t ccr0_high, ccr0_low;


    timer = req_msg.cur_time;
    TACTL = TASSEL_2 + MC_1 + ID_3;
    delay_cycle = (uint32_t)timer * 137500UL;
    ccr0_high = (uint16_t)(delay_cycle >> 16);
    ccr0_low = (uint16_t)(delay_cycle & 0xFFFF);

    if (ccr0_high > 0) {
        while (timer > 0) {
            if (timer >= 65536) {
                TACCR0 = 0xFFFF;
                timer -= 65536;
            } else {
                TACCR0 = (uint16_t)((uint32_t)timer * 137500UL);
                timer = 0;
            }
            TAR = 0x00;
            while ((TACCR0 - TAR) != 0) {
            }
        }
    } else {
        TACCR0 = ccr0_low;
        TAR = 0x00;
        while ((TACCR0 - TAR) != 0) {
        }
    }

    memset(key, 0, SIZE_KEY);
    memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY);
    uint8_t auth_rep_refresh[SIZE_SIGNATURE] = {0};
    hmac((uint8_t *)auth_rep_refresh, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)&req_msg, (uint32_t)(sizeof(req_msg)));

    struct att_rep att_rep_ref;
    att_rep_ref.msg_type = MSG_TYPE_REP_REF;
    att_rep_ref.dev_id = dev_id;
    att_rep_ref.par = parent;
    att_rep_ref.seq = cur_seq;
    memcpy(att_rep_ref.auth_rep, auth_rep_refresh, SIZE_HASH);
    send_buf(&att_rep_ref, sizeof(att_rep_ref));
    break;

  case MSG_TYPE_REP:;
    // if rep continue to rep_refresh (they're identical)
  case MSG_TYPE_REP_REF:;
    struct att_rep rep_msg;
    if (rx_start > rx_end)
    {
      my_memcpy((uint8_t *)&rep_msg, &rxdata[rx_start], RING_BUF_SIZE - rx_start);
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

__attribute__((section(".do_mac.body"))) void CASU_update_authenticate()
{
  uint8_t key[SIZE_KEY] = {0};

  memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY);

  /* Work around for version number of existing software */
  // Check if the version number is greater than the previous one.
  if (*(uint16_t *)((uint8_t *)B_EP_START + OFFSET_VER_INFO) <= *(uint16_t *)((uint8_t *)EXISTING_SW_VERSION))
  {
    CASU_jump_to_ER_routine_init();
  }

  // Compute HMAC on the bEP.
  uint8_t signature[SIZE_SIGNATURE] = {0};
  uint8_t *bEP_min = (uint8_t *)(*((uint16_t *)B_EP_START));
  uint16_t bEP_size = ((*(uint16_t *)B_EP_END) - (*(uint16_t *)B_EP_START)) + 2;

  hmac((uint8_t *)signature, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)bEP_min, (uint32_t)bEP_size);

  // Check if signature == SIG_RESP_ADDR. If yes, jump to CASU_update_install()
  if (secure_memcmp(signature, (uint8_t *)SIG_RESP_ADDR, sizeof(signature)) == 0)
  {
    CASU_update_install();
  }

  // Otherwise, jump to CASU_jump_to_ER_routine_init()
  CASU_jump_to_ER_routine_init();
}

__attribute__((section(".do_mac.body"))) void CASU_update_install()
{

  // Set SCACHE_FLAG to 1
  if (*(uint8_t *)SCACHE_FLAG == 0)
  {
    *(uint8_t *)SCACHE_FLAG = 1;
  }

  // Check whether EP_START == B_EP_START, if not, copy B_EP_START to EP_START
  if (*(uint16_t *)EP_START != (*(uint16_t *)B_EP_START))
  {
    *(uint16_t *)EP_START = *(uint16_t *)B_EP_START;
    *(uint16_t *)EP_END = *(uint16_t *)B_EP_END;
  }

  // Copy new IVT (from software at B_EP_START) to SCACHE_IVT and make sure Reset handler is 0xA000
  memcpy((uint8_t *)SCACHE_IVT, (uint8_t *)(*(uint16_t *)B_EP_END) + 2 - SIZE_IVT, SIZE_IVT);

  // Compute response and store to SIG_RESP_ADDR
  uint8_t key[SIZE_KEY] = {0};
  memcpy(key, (uint8_t *)KEY_ADDR, SIZE_KEY);
  uint8_t response_body[SIZE_VER_INFO + SIZE_NONCE] = {0};
  *(uint16_t *)response_body = *(uint16_t *)((uint8_t *)(*(uint16_t *)B_EP_START) + OFFSET_VER_INFO);
  memcpy(response_body + SIZE_VER_INFO, (uint8_t *)(*(uint16_t *)B_EP_START) + OFFSET_NONCE, SIZE_NONCE);
  hmac((uint8_t *)SIG_RESP_ADDR, (uint8_t *)key, (uint32_t)SIZE_KEY, response_body, (uint32_t)(SIZE_VER_INFO + SIZE_NONCE));

  // Set SCACHE_FLAG to 0
  *(uint8_t *)SCACHE_FLAG = 0;

  CASU_jump_to_ER_routine();
}

__attribute__((section(".do_mac.body"))) void CASU_jump_to_ER_routine_init()
{

  // Read the ER start address from EP_START and store in r5
  __asm__ volatile("mov    #0x0140,   r5"
                   "\n\t");
  __asm__ volatile("mov    @(r5),     r5"
                   "\n\t");

  // Set the Stack Pointer to ER Stack before leaving CASU
  __asm__ volatile("mov    #0x6200,     r1"
                   "\n\t");
  __asm__ volatile("clr    r3"
                   "\n\t");
  __asm__ volatile("clr    r4"
                   "\n\t");
  __asm__ volatile("clr    r6"
                   "\n\t");
  __asm__ volatile("clr    r7"
                   "\n\t");
  __asm__ volatile("clr    r8"
                   "\n\t");
  __asm__ volatile("clr    r9"
                   "\n\t");
  __asm__ volatile("clr    r10"
                   "\n\t");
  __asm__ volatile("clr    r11"
                   "\n\t");
  __asm__ volatile("clr    r12"
                   "\n\t");
  __asm__ volatile("clr    r13"
                   "\n\t");
  __asm__ volatile("clr    r14"
                   "\n\t");
  __asm__ volatile("clr    r15"
                   "\n\t");

  // Jump to CASU_exit
  __eint();
  __asm__ volatile("br      #__mac_leave"
                   "\n\t");
}

__attribute__((section(".do_mac.body"))) void CASU_jump_to_ER_routine()
{

  // Read the ER start address from EP_START and store in r5
  __asm__ volatile("mov    #0x0140,   r5"
                   "\n\t");
  __asm__ volatile("mov    @(r5),     r5"
                   "\n\t");
  // Jump to the starting of the software. The header size is 36
  __asm__ volatile("add    #36,     r5"
                   "\n\t");

  // Set the Stack Pointer to ER Stack before leaving CASU
  __asm__ volatile("mov    #0x6200,     r1"
                   "\n\t");
  __asm__ volatile("clr    r3"
                   "\n\t");
  __asm__ volatile("clr    r4"
                   "\n\t");
  __asm__ volatile("clr    r6"
                   "\n\t");
  __asm__ volatile("clr    r7"
                   "\n\t");
  __asm__ volatile("clr    r8"
                   "\n\t");
  __asm__ volatile("clr    r9"
                   "\n\t");
  __asm__ volatile("clr    r10"
                   "\n\t");
  __asm__ volatile("clr    r11"
                   "\n\t");
  __asm__ volatile("clr    r12"
                   "\n\t");
  __asm__ volatile("clr    r13"
                   "\n\t");
  __asm__ volatile("clr    r14"
                   "\n\t");
  __asm__ volatile("clr    r15"
                   "\n\t");

  // Jump to CASU_exit
  __eint();
  __asm__ volatile("br      #__mac_leave"
                   "\n\t");
}

__attribute__((section(".do_mac.body"))) int secure_memcmp(const uint8_t *s1, const uint8_t *s2, int size)
{
  int res = 0;
  int first = 1;
  for (int i = 0; i < size; i++)
  {
    if (first == 1 && s1[i] > s2[i])
    {
      res = 1;
      first = 0;
    }
    else if (first == 1 && s1[i] < s2[i])
    {
      res = -1;
      first = 0;
    }
  }
  return res;
}

/* [CASU-SW] Exit function */
__attribute__((section(".do_mac.leave"))) __attribute__((naked)) void CASU_exit()
{
  __asm__ volatile("br   r5"
                   "\n\t");
}

/* Update routine in SW */
void CASU_secure_update(uint8_t *update_code, uint8_t *signature)
{

  uint16_t new_ep_start = 0;
  uint16_t new_ep_end = 0;
  uint16_t update_code_size = *(uint16_t *)(update_code + OFFSET_SW_SIZE);
  // Copy input signature to SIG_RESP_ADDR:
  my_memcpy((uint8_t *)SIG_RESP_ADDR, signature, SIZE_SIGNATURE);

  // Check EP_START and decide where to write the update_code.
  if ((*(uint16_t *)EP_START >= ER_FIRST_SW_START) && (*(uint16_t *)EP_START < ER_SECOND_SW_START))
  {
    new_ep_start = ER_SECOND_SW_START;
  }
  else
  {
    new_ep_start = ER_FIRST_SW_START;
  }
  new_ep_end = new_ep_start + update_code_size - 2;

  // Write the update_code at that location and update B_EP_START.
  my_memcpy((uint8_t *)new_ep_start, update_code, update_code_size);
  *(uint16_t *)B_EP_START = new_ep_start;
  *(uint16_t *)B_EP_END = new_ep_end;

  // Set r4 as 1
  __asm__ volatile("mov    #1,  r4"
                   "\n\t");
  /*  __asm__ volatile("push r2" "\n\t");
    __asm__ volatile("mov    #0,  r4" "\n\t");
    __asm__ volatile("push r2" "\n\t");
    __asm__ volatile("mov    #1,  r4" "\n\t");
    __asm__ volatile("push r2" "\n\t");
    __asm__ volatile("mov    #0,  r4" "\n\t");
    __asm__ volatile("push r2" "\n\t");
    __asm__ volatile("mov    #1,  r4" "\n\t");
    __asm__ volatile("push r2" "\n\t");
    __asm__ volatile("mov    #0,  r4" "\n\t");
    __asm__ volatile("push r2" "\n\t");
    __asm__ volatile("mov    #1,  r4" "\n\t");
    __asm__ volatile("pop r4" "\n\t");*/

  // Call CASU:
  tcb_entry();
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
}
