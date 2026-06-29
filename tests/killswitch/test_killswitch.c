/** @file
  Kill-Switch Unit Tests

  Host-compilable test suite for the pure-logic functions in KillSwitch.c.
  Tests ParseDateString, CompareDates, and ParseUuidString.

  Build: gcc -std=c11 -Wall -Wextra -I. -I./edk2_includes -o test_killswitch test_killswitch.c
  Run:   ./test_killswitch

**/

#include <stdio.h>

#include "edk2_stubs.h"

/* Include the source directly — KillSwitch.h is suppressed via __KILL_SWITCH_H__ guard */
#include "../../src/BootkitPkg/DxeInject/KillSwitch.c"

/* ===== Minimal test framework ===== */

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) \
  do { \
    g_tests_run++; \
    printf("  [TEST] %s ... ", name);

#define TEST_END \
    g_tests_passed++; \
    printf("PASS\n"); \
  } while (0)

#define ASSERT_TRUE(expr) \
  do { \
    if (!(expr)) { \
      printf("FAIL\n"); \
      printf("         Assert failed: %s\n", #expr); \
      printf("         at %s:%d\n", __FILE__, __LINE__); \
      g_tests_failed++; \
      break; \
    } \
  } while (0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(expected, actual) \
  do { \
    if ((expected) != (actual)) { \
      printf("FAIL\n"); \
      printf("         Expected: %lld, Got: %lld\n", \
             (long long)(expected), (long long)(actual)); \
      printf("         at %s:%d\n", __FILE__, __LINE__); \
      g_tests_failed++; \
      break; \
    } \
  } while (0)

/* ===== ParseDateString tests ===== */

static void test_parse_date_valid_basic(void) {
  TEST("ParseDateString: valid date 2027-12-31");
  UINT16 year; UINT8 month, day;
  ASSERT_TRUE(ParseDateString("2027-12-31", &year, &month, &day));
  ASSERT_EQ(2027, year);
  ASSERT_EQ(12, month);
  ASSERT_EQ(31, day);
  TEST_END;
}

static void test_parse_date_valid_leap_day(void) {
  TEST("ParseDateString: valid leap day 2024-02-29");
  UINT16 year; UINT8 month, day;
  ASSERT_TRUE(ParseDateString("2024-02-29", &year, &month, &day));
  ASSERT_EQ(2024, year);
  ASSERT_EQ(2, month);
  ASSERT_EQ(29, day);
  TEST_END;
}

static void test_parse_date_invalid_leap_day(void) {
  TEST("ParseDateString: invalid leap day 2023-02-29");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("2023-02-29", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_invalid_month(void) {
  TEST("ParseDateString: invalid month 13");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("2024-13-01", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_invalid_day(void) {
  TEST("ParseDateString: invalid day 32");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("2024-01-32", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_wrong_length(void) {
  TEST("ParseDateString: wrong length (no dashes)");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("20241231", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_wrong_separator(void) {
  TEST("ParseDateString: wrong separator (slashes)");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("2024/01/01", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_null_input(void) {
  TEST("ParseDateString: NULL string");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString(NULL, &year, &month, &day));
  TEST_END;
}

static void test_parse_date_null_output(void) {
  TEST("ParseDateString: NULL output pointers");
  ASSERT_FALSE(ParseDateString("2024-01-01", NULL, NULL, NULL));
  TEST_END;
}

static void test_parse_date_boundary_year_2000(void) {
  TEST("ParseDateString: boundary year 2000");
  UINT16 year; UINT8 month, day;
  ASSERT_TRUE(ParseDateString("2000-01-01", &year, &month, &day));
  ASSERT_EQ(2000, year);
  TEST_END;
}

static void test_parse_date_boundary_year_2100(void) {
  TEST("ParseDateString: boundary year 2100");
  UINT16 year; UINT8 month, day;
  ASSERT_TRUE(ParseDateString("2100-03-01", &year, &month, &day));
  ASSERT_EQ(2100, year);
  TEST_END;
}

static void test_parse_date_out_of_range_year_low(void) {
  TEST("ParseDateString: year < 2000 rejected");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("1999-12-31", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_out_of_range_year_high(void) {
  TEST("ParseDateString: year > 2100 rejected");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("2101-01-01", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_century_leap_year(void) {
  TEST("ParseDateString: 2100 is NOT a leap year (Feb 29 rejected)");
  UINT16 year; UINT8 month, day;
  ASSERT_FALSE(ParseDateString("2100-02-29", &year, &month, &day));
  TEST_END;
}

static void test_parse_date_quad_century_leap_year(void) {
  TEST("ParseDateString: 2000 IS a leap year (Feb 29 accepted)");
  UINT16 year; UINT8 month, day;
  ASSERT_TRUE(ParseDateString("2000-02-29", &year, &month, &day));
  ASSERT_EQ(29, day);
  TEST_END;
}

/* ===== CompareDates tests ===== */

static void test_compare_dates_equal(void) {
  TEST("CompareDates: equal dates return 0");
  ASSERT_EQ(0, CompareDates(2024, 6, 15, 2024, 6, 15));
  TEST_END;
}

static void test_compare_dates_year_before(void) {
  TEST("CompareDates: earlier year is negative");
  ASSERT_TRUE(CompareDates(2023, 12, 31, 2024, 1, 1) < 0);
  TEST_END;
}

static void test_compare_dates_year_after(void) {
  TEST("CompareDates: later year is positive");
  ASSERT_TRUE(CompareDates(2025, 1, 1, 2024, 12, 31) > 0);
  TEST_END;
}

static void test_compare_dates_month_before(void) {
  TEST("CompareDates: same year, earlier month is negative");
  ASSERT_TRUE(CompareDates(2024, 3, 15, 2024, 7, 15) < 0);
  TEST_END;
}

static void test_compare_dates_month_after(void) {
  TEST("CompareDates: same year, later month is positive");
  ASSERT_TRUE(CompareDates(2024, 11, 1, 2024, 2, 28) > 0);
  TEST_END;
}

static void test_compare_dates_day_before(void) {
  TEST("CompareDates: same year+month, earlier day is negative");
  ASSERT_TRUE(CompareDates(2024, 6, 1, 2024, 6, 30) < 0);
  TEST_END;
}

/* ===== ParseUuidString tests ===== */

static void test_parse_uuid_valid(void) {
  TEST("ParseUuidString: valid UUID");
  UINT8 bytes[16];
  ASSERT_EQ(EFI_SUCCESS, ParseUuidString("01234567-89ab-cdef-0123-456789abcdef", bytes));
  ASSERT_EQ(0x01, bytes[0]);
  ASSERT_EQ(0x23, bytes[1]);
  ASSERT_EQ(0x45, bytes[2]);
  ASSERT_EQ(0x67, bytes[3]);
  ASSERT_EQ(0x89, bytes[4]);
  ASSERT_EQ(0xab, bytes[5]);
  ASSERT_EQ(0xcd, bytes[6]);
  ASSERT_EQ(0xef, bytes[7]);
  TEST_END;
}

static void test_parse_uuid_all_zeros(void) {
  TEST("ParseUuidString: all zeros");
  UINT8 bytes[16];
  ASSERT_EQ(EFI_SUCCESS, ParseUuidString("00000000-0000-0000-0000-000000000000", bytes));
  for (int i = 0; i < 16; i++) {
    ASSERT_EQ(0x00, bytes[i]);
  }
  TEST_END;
}

static void test_parse_uuid_all_ff(void) {
  TEST("ParseUuidString: all 0xFF");
  UINT8 bytes[16];
  ASSERT_EQ(EFI_SUCCESS, ParseUuidString("ffffffff-ffff-ffff-ffff-ffffffffffff", bytes));
  for (int i = 0; i < 16; i++) {
    ASSERT_EQ(0xff, bytes[i]);
  }
  TEST_END;
}

static void test_parse_uuid_wrong_length(void) {
  TEST("ParseUuidString: wrong length");
  UINT8 bytes[16];
  ASSERT_EQ(EFI_INVALID_PARAMETER, ParseUuidString("0123456789abcdef", bytes));
  TEST_END;
}

static void test_parse_uuid_missing_dashes(void) {
  TEST("ParseUuidString: missing dashes (36 chars but no dashes)");
  UINT8 bytes[16];
  ASSERT_EQ(EFI_INVALID_PARAMETER, ParseUuidString("0123456789abcdef0123456789abcdef0123", bytes));
  TEST_END;
}

static void test_parse_uuid_wrong_dash_positions(void) {
  TEST("ParseUuidString: dashes in wrong positions");
  UINT8 bytes[16];
  ASSERT_EQ(EFI_INVALID_PARAMETER, ParseUuidString("0123-4567-89ab-cdef-0123456789abcdef", bytes));
  TEST_END;
}

static void test_parse_uuid_null_string(void) {
  TEST("ParseUuidString: NULL string");
  UINT8 bytes[16];
  ASSERT_EQ(EFI_INVALID_PARAMETER, ParseUuidString(NULL, bytes));
  TEST_END;
}

static void test_parse_uuid_null_output(void) {
  TEST("ParseUuidString: NULL output buffer");
  ASSERT_EQ(EFI_INVALID_PARAMETER, ParseUuidString("01234567-89ab-cdef-0123-456789abcdef", NULL));
  TEST_END;
}

/* ===== Main ===== */

int main(void) {
  printf("=== Barzakh Kill-Switch Unit Tests ===\n\n");

  printf("[ParseDateString]\n");
  test_parse_date_valid_basic();
  test_parse_date_valid_leap_day();
  test_parse_date_invalid_leap_day();
  test_parse_date_invalid_month();
  test_parse_date_invalid_day();
  test_parse_date_wrong_length();
  test_parse_date_wrong_separator();
  test_parse_date_null_input();
  test_parse_date_null_output();
  test_parse_date_boundary_year_2000();
  test_parse_date_boundary_year_2100();
  test_parse_date_out_of_range_year_low();
  test_parse_date_out_of_range_year_high();
  test_parse_date_century_leap_year();
  test_parse_date_quad_century_leap_year();

  printf("\n[CompareDates]\n");
  test_compare_dates_equal();
  test_compare_dates_year_before();
  test_compare_dates_year_after();
  test_compare_dates_month_before();
  test_compare_dates_month_after();
  test_compare_dates_day_before();

  printf("\n[ParseUuidString]\n");
  test_parse_uuid_valid();
  test_parse_uuid_all_zeros();
  test_parse_uuid_all_ff();
  test_parse_uuid_wrong_length();
  test_parse_uuid_missing_dashes();
  test_parse_uuid_wrong_dash_positions();
  test_parse_uuid_null_string();
  test_parse_uuid_null_output();

  printf("\n=== Results: %d passed, %d failed, %d total ===\n",
         g_tests_passed, g_tests_failed, g_tests_run);

  return g_tests_failed > 0 ? 1 : 0;
}
