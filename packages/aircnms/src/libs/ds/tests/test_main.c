#include <stdio.h>
#include <stdlib.h>

void run_test_ds_tree(void);

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("Running unit tests for libds...\n");

    run_test_ds_tree();

    printf("All tests completed.\n");
    return EXIT_SUCCESS;
}