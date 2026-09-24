#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "unixcomm.h"

static void test_unixcomm_init(void **state)
{
    (void)state;
    unixcomm_global_config_t config = {0};

    assert_true(unixcomm_init(&config));
    assert_true(unixcomm_is_initialized());
    unixcomm_cleanup();
}

static void test_unixcomm_config_init(void **state)
{
    (void)state;
    unixcomm_config_t config;

    assert_true(unixcomm_config_init(&config));
    assert_true(unixcomm_config_validate(&config));
}

static void test_unixcomm_config_set_socket_path(void **state)
{
    (void)state;
    unixcomm_config_t config;

    assert_true(unixcomm_config_init(&config));
    assert_true(unixcomm_config_set_socket_path(&config, "/tmp/test.sock"));
    assert_true(unixcomm_config_validate(&config));
}

static void test_unixcomm_config_set_timeout(void **state)
{
    (void)state;
    unixcomm_config_t config;

    assert_true(unixcomm_config_init(&config));
    assert_true(unixcomm_config_set_timeout(&config, 5.0));
    assert_true(unixcomm_config_validate(&config));
}

static void test_unixcomm_config_set_max_pending(void **state)
{
    (void)state;
    unixcomm_config_t config;

    assert_true(unixcomm_config_init(&config));
    assert_true(unixcomm_config_set_max_pending(&config, 20));
    assert_true(unixcomm_config_validate(&config));
}

static void test_unixcomm_config_set_target_process(void **state)
{
    (void)state;
    unixcomm_config_t config;

    assert_true(unixcomm_config_init(&config));
    assert_true(unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_SM));
    assert_true(unixcomm_config_validate(&config));
}

static void test_unixcomm_request_init(void **state)
{
    (void)state;
    unixcomm_request_t request;

    assert_true(unixcomm_request_init(&request, "test_sender"));
    assert_string_equal(request.sender, "test_sender");
    assert_int_equal(request.version, 1);
}

static void test_unixcomm_response_init(void **state)
{
    (void)state;
    unixcomm_request_t request;
    unixcomm_response_t response;

    unixcomm_request_init(&request, "sender");
    request.sequence = 123;

    assert_true(unixcomm_response_init(&response, &request));
    assert_int_equal(response.sequence, 123);
}

void run_test_unixcomm(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_unixcomm_init),
        cmocka_unit_test(test_unixcomm_config_init),
        cmocka_unit_test(test_unixcomm_config_set_socket_path),
        cmocka_unit_test(test_unixcomm_config_set_timeout),
        cmocka_unit_test(test_unixcomm_config_set_max_pending),
        cmocka_unit_test(test_unixcomm_config_set_target_process),
        cmocka_unit_test(test_unixcomm_request_init),
        cmocka_unit_test(test_unixcomm_response_init),
    };

    cmocka_run_group_tests(tests, NULL, NULL);
}