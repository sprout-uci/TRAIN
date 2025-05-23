#include <stdio.h>
#include "hardware.h"
#define WDTCTL_ 0x0120 /* Watchdog Timer Control */
#define WDTHOLD (0x0080)
#define WDTPW (0x5A00)

#define SIG_RESP_ADDR     (0x03D0)

#define ACKTO    'b'

extern void CASU_secure_update(uint8_t *update_code, uint8_t *signature);
extern void my_memset(uint8_t *ptr, int len, uint8_t val);
extern void my_memcpy(uint8_t *dst, uint8_t *src, int size);

static uint8_t update_code[] = {
    0x06, 0x01, 0x01, 0x00, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x55, 0x42, 0x20, 0x01,
    0x35, 0xd0, 0x08, 0x5a, 0x82, 0x45, 0x00, 0x12,
    0x31, 0x40, 0x00, 0x62, 0x3f, 0x40, 0x00, 0x00,
    0x0f, 0x93, 0x08, 0x24, 0x92, 0x42, 0x00, 0x12,
    0x20, 0x01, 0x2f, 0x83, 0x9f, 0x4f, 0xe6, 0xf0,
    0x00, 0x02, 0xf8, 0x23, 0x3f, 0x40, 0x00, 0x00,
    0x0f, 0x93, 0x07, 0x24, 0x92, 0x42, 0x00, 0x12,
    0x20, 0x01, 0x1f, 0x83, 0xcf, 0x43, 0x00, 0x12,
    0xf9, 0x23, 0xb0, 0x12, 0x9c, 0xf0, 0x3e, 0x40,
    0x0a, 0x00, 0x3f, 0x40, 0xf4, 0x01, 0xb0, 0x12,
    0xa6, 0xf0, 0xff, 0x3f, 0x32, 0xd0, 0xf0, 0x00,
    0xfd, 0x3f, 0x30, 0x40, 0xe4, 0xf0, 0x21, 0x83,
    0x81, 0x43, 0x00, 0x00, 0x2e, 0x41, 0x0e, 0x9f,
    0x07, 0x2c, 0x2e, 0x41, 0x1e, 0x53, 0x81, 0x4e,
    0x00, 0x00, 0x2e, 0x41, 0x0e, 0x9f, 0xf9, 0x2b,
    0x21, 0x53, 0x30, 0x41, 0xf2, 0x43, 0x1a, 0x00,
    0xc2, 0x43, 0x19, 0x00, 0x30, 0x41, 0x0b, 0x12,
    0x0a, 0x12, 0x09, 0x12, 0x08, 0x12, 0x09, 0x4f,
    0x0e, 0x93, 0x13, 0x24, 0x08, 0x4e, 0x0a, 0x43,
    0x3b, 0x40, 0x19, 0x00, 0xfb, 0x40, 0x55, 0x00,
    0x00, 0x00, 0x0f, 0x49, 0xb0, 0x12, 0x7e, 0xf0,
    0xfb, 0x40, 0xaa, 0xff, 0x00, 0x00, 0x0f, 0x49,
    0xb0, 0x12, 0x7e, 0xf0, 0x1a, 0x53, 0x0a, 0x98,
    0xef, 0x23, 0x38, 0x41, 0x39, 0x41, 0x3a, 0x41,
    0x3b, 0x41, 0x30, 0x41, 0x00, 0x13, 0x9a, 0xe0,
    0x9a, 0xe0, 0x9a, 0xe0, 0x9a, 0xe0, 0x9a, 0xe0,
    0x9a, 0xe0, 0x9a, 0xe0, 0x9a, 0xe0, 0x9a, 0xe0,
    0x9a, 0xe0, 0x9a, 0xe0, 0x9a, 0xe0, 0x9a, 0xe0,
    0x9a, 0xe0, 0x9a, 0xe0, 0x00, 0xa0};

static uint8_t signature[32] = {
    0xe2, 0x3a, 0xfc, 0x1d, 0x3f, 0x55, 0xbe, 0x7d,
    0xaf, 0x42, 0x75, 0xcb, 0x4c, 0x4d, 0x77, 0x39,
    0x14, 0x87, 0xb6, 0x6d, 0x4f, 0x37, 0x6d, 0xfc,
    0xea, 0x5f, 0x73, 0x84, 0x27, 0x9c, 0x7a, 0x89};

void delayMicroseconds(unsigned int delay)
{
  volatile unsigned int j;
  for (j = 0; j < delay; j++);
}

void initLed() 
{
  P3DIR  =  0xFF;
  P3OUT  =  0x00;
}


int main()
{
  /*this WTD stuff needs to go inside of wrapper*/
  // Switch off the WTD
  __eint();
  uint32_t *wdt = (uint32_t *)(WDTCTL_);
  *wdt = WDTPW | WDTHOLD;


//TO IMPLEMENT
//  UART_BAUD = BAUD;                   // Init UART
 // UART_CTL  = UART_EN | UART_IEN_RX;  

  int i;
  const int iter = 5;

  // Set the LED
  initLed();
  // Enable interrupts: NO YOU CANT DO THAT HERE INTERRUPTS CAN ONLY BE ENABLED OR DISABLED WITHIN THE TCB  
 // __eint();
  //Sample application: Blink P3 for 200ms for 5 times;
  
  for (i=0; i<iter; i++) {
    P3OUT = 0x55;
    delayMicroseconds(20);
    P3OUT = 0xAA;
    delayMicroseconds(20);
  }


  //this will never get called...
  // Call Secure Update
  //what if i just comment this out LOL
  //i'll keep it for now...
  
  while(1)
  {
    i++;
    delayMicroseconds(200000);
    P3OUT = ~P3OUT;
    if(i > 500000)
    {
      i = 0;
    }
 }

 // CASU_secure_update(update_code, signature);

  // Jump to zero, nothing. Note: PC should never come here.
  __asm__ volatile("br #0x0000" "\n\t");

  return 0;
}