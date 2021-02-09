#ifndef KEYCARD_UNITTEST_TRANSPORT_H
#define KEYCARD_UNITTEST_TRANSPORT_H

#ifdef KEYCARD_UNIT_TEST_MAIN

#include <stdio.h>

void unittest_uart_begin() {

}

void unittest_uart_putchar(char c) {
  putchar(c);
}

void unittest_uart_flush() {
  fflush(stdout);
}

void unittest_uart_end() {

}

#endif
#endif
