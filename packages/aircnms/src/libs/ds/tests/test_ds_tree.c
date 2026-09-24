#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ds_tree.h"

typedef struct test_node {
    ds_tree_node_t node;
    int key;
    char *value;
} test_node_t;

static int test_cmp(const void *a, const void *b)
{
    const int *ia = a;
    const int *ib = b;
    return *ia - *ib;
}

static void test_ds_tree_init(void **state)
{
    (void)state;
    ds_tree_t tree;
    ds_tree_init(&tree, test_cmp, test_node_t, node);

    assert_null(tree.ot_root);
    assert_ptr_equal(tree.ot_cmp_fn, test_cmp);
    assert_int_equal(tree.ot_cof, offsetof(test_node_t, node));
}

static void test_ds_tree_insert_find(void **state)
{
    (void)state;
    ds_tree_t tree;
    test_node_t node1, node2;
    int key1 = 10, key2 = 20;

    ds_tree_init(&tree, test_cmp, test_node_t, node);

    node1.key = key1;
    node1.value = "value1";
    ds_tree_insert(&tree, &node1, &key1);

    node2.key = key2;
    node2.value = "value2";
    ds_tree_insert(&tree, &node2, &key2);

    test_node_t *found1 = ds_tree_find(&tree, &key1);
    test_node_t *found2 = ds_tree_find(&tree, &key2);

    assert_ptr_equal(found1, &node1);
    assert_ptr_equal(found2, &node2);
    assert_int_equal(found1->key, key1);
    assert_string_equal(found1->value, "value1");
}

static void test_ds_tree_find_not_found(void **state)
{
    (void)state;
    ds_tree_t tree;
    test_node_t node1;
    int key1 = 10, key_missing = 30;

    ds_tree_init(&tree, test_cmp, test_node_t, node);

    node1.key = key1;
    ds_tree_insert(&tree, &node1, &key1);

    test_node_t *found = ds_tree_find(&tree, &key_missing);
    assert_null(found);
}

static void test_ds_tree_is_empty(void **state)
{
    (void)state;
    ds_tree_t tree;

    ds_tree_init(&tree, test_cmp, test_node_t, node);
    assert_true(ds_tree_is_empty(&tree));

    test_node_t node1;
    int key1 = 10;
    node1.key = key1;
    ds_tree_insert(&tree, &node1, &key1);

    assert_false(ds_tree_is_empty(&tree));
}

static void test_ds_tree_head_tail(void **state)
{
    (void)state;
    ds_tree_t tree;
    test_node_t node1, node2, node3;
    int key1 = 10, key2 = 5, key3 = 15;

    ds_tree_init(&tree, test_cmp, test_node_t, node);

    node1.key = key1;
    ds_tree_insert(&tree, &node1, &key1);

    node2.key = key2;
    ds_tree_insert(&tree, &node2, &key2);

    node3.key = key3;
    ds_tree_insert(&tree, &node3, &key3);

    test_node_t *head = ds_tree_head(&tree);
    test_node_t *tail = ds_tree_tail(&tree);

    assert_ptr_equal(head, &node2); // smallest key
    assert_ptr_equal(tail, &node3); // largest key
}

static void test_ds_tree_next_prev(void **state)
{
    (void)state;
    ds_tree_t tree;
    test_node_t node1, node2, node3;
    int key1 = 10, key2 = 5, key3 = 15;

    ds_tree_init(&tree, test_cmp, test_node_t, node);

    node1.key = key1;
    ds_tree_insert(&tree, &node1, &key1);

    node2.key = key2;
    ds_tree_insert(&tree, &node2, &key2);

    node3.key = key3;
    ds_tree_insert(&tree, &node3, &key3);

    // In-order: node2 (5), node1 (10), node3 (15)
    test_node_t *next1 = ds_tree_next(&tree, &node2);
    test_node_t *next2 = ds_tree_next(&tree, &node1);
    test_node_t *prev2 = ds_tree_prev(&tree, &node1);
    test_node_t *prev3 = ds_tree_prev(&tree, &node3);

    assert_ptr_equal(next1, &node1);
    assert_ptr_equal(next2, &node3);
    assert_ptr_equal(prev2, &node2);
    assert_ptr_equal(prev3, &node1);
}

static void test_ds_tree_remove(void **state)
{
    (void)state;
    ds_tree_t tree;
    test_node_t node1, node2;
    int key1 = 10, key2 = 20;

    ds_tree_init(&tree, test_cmp, test_node_t, node);

    node1.key = key1;
    ds_tree_insert(&tree, &node1, &key1);

    node2.key = key2;
    ds_tree_insert(&tree, &node2, &key2);

    // Remove node1
    ds_tree_remove(&tree, &node1);

    test_node_t *found1 = ds_tree_find(&tree, &key1);
    test_node_t *found2 = ds_tree_find(&tree, &key2);

    assert_null(found1);
    assert_ptr_equal(found2, &node2);
}

static void test_ds_tree_foreach(void **state)
{
    (void)state;
    ds_tree_t tree;
    test_node_t node1, node2, node3;
    int key1 = 10, key2 = 5, key3 = 15;
    int count = 0;

    ds_tree_init(&tree, test_cmp, test_node_t, node);

    node1.key = key1;
    ds_tree_insert(&tree, &node1, &key1);

    node2.key = key2;
    ds_tree_insert(&tree, &node2, &key2);

    node3.key = key3;
    ds_tree_insert(&tree, &node3, &key3);

    test_node_t *p;
    ds_tree_foreach(&tree, p) {
        count++;
        assert_in_range(p->key, 5, 15);
    }

    assert_int_equal(count, 3);
}

void run_test_ds_tree(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ds_tree_init),
        cmocka_unit_test(test_ds_tree_insert_find),
        cmocka_unit_test(test_ds_tree_find_not_found),
        cmocka_unit_test(test_ds_tree_is_empty),
        cmocka_unit_test(test_ds_tree_head_tail),
        cmocka_unit_test(test_ds_tree_next_prev),
        cmocka_unit_test(test_ds_tree_remove),
        cmocka_unit_test(test_ds_tree_foreach),
    };

    cmocka_run_group_tests(tests, NULL, NULL);
}