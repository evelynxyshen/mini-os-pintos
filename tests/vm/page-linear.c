/* Encrypts, then decrypts, 2 MB of memory and verifies that the
   values are as they should be. */

#include <string.h>
#include "tests/arc4.h"
#include "tests/lib.h"
#include "tests/main.h"

#define SIZE (2 * 1024 * 1024)
//#define SIZE (1600 * 1024)

static char buf[SIZE];

void
test_main (void)
{
//  printf("BUFF ADDR: 0x%x dec%d 0x%x dec%d\n", buf, (uint32_t)buf>>12, buf+SIZE, (uint32_t)(buf+SIZE)>>12);
  struct arc4 arc4;
//  msg ("cmd 1");
  size_t i;
//  msg ("cmd 2");

  /* Initialize to 0x5a. */
  msg ("initialize");
  memset (buf, 0x5a, sizeof buf);
  msg ("read pass one");

  memset (buf, 0x5a, sizeof buf);
  msg ("read pass two");

  /* Check that it's all 0x5a. */
  msg ("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
      fail ("byte %zu != 0x5a", i);

  /* Encrypt zeros. */
  msg ("read/modify/write pass one");
  arc4_init (&arc4, "foobar", 6);
  arc4_crypt (&arc4, buf, SIZE);

  /* Decrypt back to zeros. */
  msg ("read/modify/write pass two");
  arc4_init (&arc4, "foobar", 6);
  arc4_crypt (&arc4, buf, SIZE);

  /* Check that it's all 0x5a. */
  msg ("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
      fail ("byte %zu != 0x5a", i);
}
