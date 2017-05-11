
#include <shmht.h>
#include <string.h>
#include<stdlib.h>
#include <stdio.h>
/*
#include <cgreen/cgreen.h>
*/
#include <math.h>
#include "../../pmacct-classifiers/flow_url.h"

/*dbj2 hash function:*/
unsigned int
dbj2_hash (void *str_)
{
	unsigned long hash = 5381;
	char *str = (char *) str_;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c;	/* hash * 33 + c */

	return (unsigned int) hash;
}

/* comparison function: */
int
str_compar (void *c1, void *c2)
{
	char *c1_str = (char *) c1;
	return !bcmp (c1, c2, strlen (c1_str));
}


/*
 * \test-name check_create_from_NotExistentFile
 * \test-function test_check_create_from_NotExistentFile
 */
void
test_check_create_from_NotExistentFile ()
{
	size_t key_size = 100;
	struct shmht *h1 =
		create_shmht ("Not_Exists_file", 16, key_size, dbj2_hash, str_compar);
}								// test_check_create_from_NotExistentFile


/*
 * \test-name check_create_HTs
 * \test-function test_check_create_HTs
 */
void
test_check_create_HTs ()
{
	struct shmht *h1 = NULL;
	struct shmht *h2 = NULL;
	size_t key_size = 100;

	h1 = create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	h2 = create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	//Destroy the global shmht
	shmht_destroy (h1);

	//Free the two references
	free (h1);
	free (h2);
}								// test_check_create_HTs


/*
 * \test-name check_create_when_inserted
 * \test-function test_check_create_when_inserted
 */
void
test_check_create_when_inserted ()
{
	struct shmht *h1 = NULL;
	struct shmht *h2 = NULL;
	char *key = "Key_for_test_check_find";
	char *stored_value = "This is the stored Value!";
	size_t key_size = 100;

	h1 = create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	int shmht_insert_ret = shmht_insert (h1, key, strlen (key)
										 , stored_value,
										 strlen (stored_value) + 1);

	h2 = create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	//Check that after creation the existing entries are still there.

	//Destroy the global shmht
	shmht_destroy (h1);

	//Free the two references
	free (h1);
	free (h2);

}								// test_check_create_when_inserted

/*
 * \test-name check_find
 * \test-function test_check_find
 */
void
test_check_find ()
{
	struct shmht *h1 = NULL;
	struct shmht *h2 = NULL;
	char *key = "Key_for_test_check_find";
	char *stored_value = "This is the stored Value!";
	size_t key_size = 100;

	h1 = create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	h2 = create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	int shmht_insert_ret = shmht_insert (h1, key, strlen (key)
										 , stored_value,
										 strlen (stored_value) + 1);

	size_t ret_size;
	void *ret = shmht_search (h1, key, strlen (key), &ret_size);


	ret = shmht_search (h2, key, strlen (key), &ret_size);



	//Destroy the global shmht
	shmht_destroy (h1);

	//Free the two references
	free (h1);
	free (h2);

}								// test_check_find

/*
 * \test-name check_iterate
 * \test-function test_check_iterate
 */
void
test_check_iterate ()
{
	struct shmht *h1 = NULL;
	size_t key_size = 30;

	h1 = create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

        int i;
	char key[30];
	char stored_value[30];
        strcpy(key, "Key_for_test_check_find");
        for (i = 12; i < 16; i++) {
            memset(stored_value, 0, 30);
            sprintf(stored_value, "This is the stored Value! %d", i);
	    int shmht_insert_ret = shmht_insert (h1, key, strlen (key), stored_value, strlen (stored_value) + 1);
        }

        for (i = 0; i < 12; i++) {
            memset(key, 0, 30);
            sprintf(key, "Key_for_test_check_find_%d", i);
            memset(stored_value, 0, 30);
            sprintf(stored_value, "This is the stored Value! %d", i);
	    int shmht_insert_ret = shmht_insert (h1, key, strlen (key), stored_value, strlen (stored_value) + 1);
        }
       
        int consumerf(void *value) {
            printf("value[%s]\n", (char *) value);
            return 0;
        }

	shmht_iterate (h1, consumerf);


	//Destroy the global shmht
	shmht_destroy (h1);

	//Free the two references
	free (h1);
}								// test_check_iterate


struct shmht *url_entries = NULL;

	  int print_url_entry(void *s) {
	      struct flow_url_data *url_data = (struct flow_url_data *) s;
	      printf("shared mem -- %s: %s->%s(%u):%s %s\n", url_data->key.protocol, url_data->key.src_ip, url_data->key.dst_ip, url_data->key.dst_port,
		url_data->method, url_data->key.path);
	      return 1;
	  }

void child() {

//        printf("child: %d url_entries:%p ", getpid(), url_entries);
//        url_entries = create_shmht ("run_tests", 16, SZ_FLOW_URL_DATA, dbj2_hash, str_compar);
        printf("child: %d url_entries:%p ", getpid(), url_entries);
        struct flow_url_data data;
        strcpy(data.key.src_ip, "1.1.1.1");
        strcpy(data.key.dst_ip, "1.1.1.2");
        data.key.dst_port = 8004;
        strcpy(data.key.protocol, "http");
        strcpy(data.key.path, "/1.1.1.3/something");

          size_t ret_size = 0;
	  void *found = shmht_search (url_entries, &data.key, SZ_FLOW_URL_KEY, &ret_size);
          //print_url_entry(found);
          printf("ret_size:%d\n", ret_size);

	  int iterated_count = shmht_iterate (url_entries, print_url_entry);
	  printf("iterated_count:%d\n", iterated_count);
}

void
test_check_iterate_2 ()
{
        url_entries = create_shmht ("run_tests", 16, SZ_FLOW_URL_DATA, dbj2_hash, str_compar);

        struct flow_url_data data;
        strcpy(data.key.src_ip, "1.1.1.1");
        strcpy(data.key.dst_ip, "1.1.1.2");
        data.key.dst_port = 8004;
        strcpy(data.key.protocol, "http");
        strcpy(data.key.path, "/1.1.1.3/something");
        strcpy(data.method, "POST");
	int shmht_insert_ret = shmht_insert (url_entries, &data.key, SZ_FLOW_URL_KEY, &data, SZ_FLOW_URL_DATA);
        printf("parent: %d url_entries:%p ", getpid(), url_entries);
        printf("shmht_insert_ret:%d\n", shmht_insert_ret);

        switch (fork()) {
        case 0: 
          child();
          exit(0);
        default: /* Parent */
          break;
        }

        sleep(30);

	//Destroy the global shmht
	shmht_destroy (url_entries);

	//Free the two references
	free (url_entries);
}								// test_check_iterate

/*
 * \test-name check_count
 * \test-function test_check_count
 */
void
test_check_count ()
{
	char *key = "Key_for_test_check_count";
	char *stored_value = "This is the stored Value!";
	size_t key_size = 100;

	//Create a shmht.
	struct shmht *h =
		create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);


	//Insert a value into.
	int shmht_insert_ret = shmht_insert (h, key, strlen (key)
										 , stored_value,
										 strlen (stored_value) + 1);

	//Count

	//Destroy the global shmht
	shmht_destroy (h);


	free (h);
}								// test_check_count


/*
 * \test-name check_long_insertions
 * \test-function test_check_long_insertions
 */
void
test_check_long_insertions ()
{
	char *key = "Key_for_test_check_count";
	char *stored_value = "This is the stored Value!";
	size_t key_size = 100;
	int i;

	//Create a shmht.
	struct shmht *h =
		create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);


	//Insert a value until all is over.
	for (i = 0; i < 100; i++) {
		int shmht_insert_ret = shmht_insert (h, key, strlen (key)
											 , stored_value,
											 strlen (stored_value) + 1);
		if (shmht_insert_ret < 0) {
			//Insert until there is no more space.
			break;
		}
	}

	int shmht_insert_ret = shmht_insert (h, key, strlen (key)
										 , stored_value,
										 strlen (stored_value) + 1);

	//Destroy the global shmht
	shmht_destroy (h);

	free (h);

}								// test_check_long_insertions


/*
 * \test-name check_flush
 * \test-function test_check_flush
 */
void
test_check_flush ()
{
	char *key = "Key_for_test_check_count";
	char *stored_value = "This is the stored Value!";
	size_t key_size = 100;
	int i;

	//Create a shmht.
	struct shmht *h =
		create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	//Create a shmht.
	struct shmht *h2 =
		create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);


	//Insert a value until all is over.
	for (i = 0; i < 100; i++) {
		int shmht_insert_ret = shmht_insert (h, key, strlen (key)
											 , stored_value,
											 strlen (stored_value) + 1);
		if (shmht_insert_ret < 0) {
			//Insert until there is no more space.
			break;
		}
	}

	//Check that we flush all the entries.

	//Destroy the global shmht
	shmht_destroy (h);


	free (h);
	free (h2);

}								// test_check_flush

/*
 * \test-name check_remove_older_entries
 * \test-function test_check_remove_older_entries
 */
void
test_check_remove_older_entries ()
{
	char *key = "Key_for_test_check_count";
	char *stored_value = "This is the stored Value!";
	size_t key_size = 100;
	int i;

	//Create a shmht.
	struct shmht *h =
		create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);


	//Insert a value 10000 times erasing the older entries.
	for (i = 0; i < 10000; i++) {
		int shmht_insert_ret = shmht_insert (h, key, strlen (key)
											 , stored_value,
											 strlen (stored_value) + 1);
		if (shmht_insert_ret < 0) {
			//remove the 30% of the older entries.
			if (shmht_remove_older_entries (h, 30) == 0) {
				break;
			}
		}
	}

	//Destroy the global shmht
	shmht_destroy (h);

	free (h);

}								// test_check_remove_older_entries


/*
 * \test-name check_number_of_removed_with_remove_older
 * \test-function test_check_number_of_removed_with_remove_older
 */
void
test_check_number_of_removed_with_remove_older ()
{
	char *key = "Key_for_test_remove_older";
	char *stored_value = "This is the stored Value!";
	size_t key_size = 100;
	int i;

	//Create a shmht.
	struct shmht *h =
		create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);

	//Insert a value until all is over.
	for (i = 0; i < 100; i++) {
		int shmht_insert_ret = shmht_insert (h, key, strlen (key)
											 , stored_value,
											 strlen (stored_value) + 1);
		if (shmht_insert_ret < 0) {
			//Insert until there is no more space.
			break;
		}
	}

	//Store the deletion of the 30% of the entries.
	int number_of_destroyed_30 = shmht_remove_older_entries (h, 30);

	//Fill the ht again:

	//Insert a value until all is over.
	for (i = 0; i < 100; i++) {
		int shmht_insert_ret = shmht_insert (h, key, strlen (key)
											 , stored_value,
											 strlen (stored_value) + 1);
		if (shmht_insert_ret < 0) {
			//Insert until there is no more space.
			break;
		}
	}
	//Get the number of destroyed entries with 50%
	int number_of_destroyed_50 = shmht_remove_older_entries (h, 50);
	//Check that with the 50% we destroy more than with the 30%

	//Destroy the global shmht
	shmht_destroy (h);


	free (h);

}								// test_check_flush

/*
 * \test-name check_create_huge_number_ht
 * \test-function test_check_create_huge_number_ht
 */
void
test_check_create_huge_number_ht ()
{
	size_t key_size = 100;
	char *key = "Key_for_huge_ht";
	char *stored_value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	int i;

	struct shmht *h[1000];
	//Create a shmht.
	for (i = 0; i != 1000; i++) {
		h[i] =
			create_shmht ("run_tests", 16, key_size, dbj2_hash, str_compar);
		if (h == NULL) {
			break;
		}
	}




	int ret_size;

	//Destroy the global shmht
	shmht_destroy (h[0]);


	for (i = 0; i != 1000; i++) {
		free (h[i]);
	}

}								// test_check_create_huge_number_ht



int main (int argc, char * argv [])
{	
/*
	TestSuite *suite = create_test_suite();

	add_test (suite, test_check_create_from_NotExistentFile);
	add_test (suite, test_check_create_HTs);
	add_test (suite, test_check_create_when_inserted);
	add_test (suite, test_check_find);
	add_test (suite, test_check_count);
	add_test (suite, test_check_long_insertions);
	add_test (suite, test_check_flush);
	add_test (suite, test_check_remove_older_entries);
	add_test (suite, test_check_number_of_removed_with_remove_older);
	add_test (suite, test_check_create_huge_number_ht);
	
	test_check_find();
	return run_test_suite(suite, create_text_reporter());
*/
	test_check_iterate_2();
}

