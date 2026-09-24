#include <stdio.h>
#include <stdlib.h>

void run_test_unixcomm(void);

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("Running unit tests for libunixcomm...\n");

    run_test_unixcomm();

    printf("All tests completed.\n");
    return EXIT_SUCCESS;
}