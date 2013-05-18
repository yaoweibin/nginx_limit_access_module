#
#===============================================================================
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;
no_root_location();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: the get test
--- http_config
limit_access_zone  zone=one:5m bucket_number=10007 type=$remote_addr;
--- config
    location / {
        root   html;
        index  index.html index.htm;

        limit_access  zone=one;
    }

    location /limit_interface {
        limit_access_interface zone=one;
    }

    location /limit_status {
        limit_access_status zone=one;
    }
--- request 
GET /
--- response_body_like: .*


=== TEST 2: the ban_list test
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_list=127.0.0.1,127.1.1.1"
--- response_body_like: ban list succeed

=== TEST 3: the following get test
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 4: the free_list test
--- request eval
"POST /limit_interface\n\n" . 
"free_type=variable&free_list=127.0.0.1,127.1.1.1"
--- response_body_like: free list succeed with 2 records

=== TEST 5: the following get test
--- request 
GET /
--- response_body_like: .*

=== TEST 6: the ban_list test again
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_list=127.0.0.1,127.1.1.1"
--- response_body_like: ban list succeed

=== TEST 7: the following get test
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 8: the expire_list test
--- request eval
"POST /limit_interface\n\n" . 
"expire_list"
--- response_body_like: Ban hash table expired.

=== TEST 9: the following get test
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 10: the show_list test
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=127.0.0.1"
--- response_body_like: ^Ban hash table:(.*)variable(.*)$

=== TEST 11: the destroy_list test
--- request eval
"POST /limit_interface\n\n" . 
"destroy_list"
--- response_body_like: Ban hash table destroyed.

=== TEST 12: the following get test
--- request 
GET /
--- response_body_like: .*

=== TEST 13: the show_list test
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=all"
--- response_body_like: ^Ban hash table:(.*)total record = 0$

=== TEST 14: the show_list test, wrong type
--- request eval
"POST /limit_interface\n\n" . 
"show_type=ip&show_list=all"
--- error_code: 400
--- response_body_like: ^.*$

=== TEST 15: the show_list test, set the output buffer size
--- http_config
limit_access_zone  zone=one:5m bucket_number=10007 type=$remote_addr;
--- config
    limit_access_variable zone=one $limit_access_deny;
    limit_access_buffer_size 1M;
    location / {
        root   html;
        index  index.html index.htm;

        if ($limit_access_deny) {
            return 403;
        }
    }

    location /limit_interface {
        limit_access_interface zone=one;
    }

    location /limit_status {
        limit_access_status zone=one;
    }
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=all"
--- response_body_like: ^Ban hash table:(.*)total record = 0$

=== TEST 16: the ban_list with variable
--- http_config
limit_access_zone  zone=one:5m bucket_number=10007 type=$http_user_agent;
--- config
    limit_access_variable zone=one $limit_access_deny;
    limit_access_buffer_size 1M;
    location / {
        root   html;
        index  index.html index.htm;

        if ($limit_access_deny) {
            return 403;
        }
    }

    location /limit_interface {
        limit_access_interface zone=one;
    }
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_expire=3600&ban_list=tom%2Ccat,jerry"
--- response_body_like: ban list succeed

=== TEST 17: the show_list with variable
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=tom%2Ccat,jerry"
--- response_body_like
^.*tom,cat", expire=.*$

=== TEST 18: the free_list with variable
--- request eval
"POST /limit_interface\n\n" . 
"free_type=variable&free_list=tom%2Ccat"
--- response_body_like: free list succeed

=== TEST 19: the show_list with variable
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=tom%2Ccat"
--- response_body_like: ^Ban hash table:(.*)there is no this record(.*)$

=== TEST 20: the ban_list with variable
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_expire=3600&ban_list=Mozilla/4.0 (Windows NT 6.1) AppleWebKit/537.4 (KHTML%2C like Gecko) Chrome/22.0.1229.0 Safari/537.4,Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.4 (KHTML%2C like Gecko) Chrome/22.0.1229.0 Safari/537.4"
--- response_body_like: ban list succeed

=== TEST 21: the show_list with variable
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.4 (KHTML%2C like Gecko) Chrome/22.0.1229.0 Safari/537.4"
--- response_body_like
^.*Chrome/22.0.1229.0 Safari/537.4", expire=.*$

=== TEST 22: test the hash_table, add ip
--- http_config
limit_access_zone  zone=one:5m bucket_number=3 type=$remote_addr;
--- config
    location / {
        root   html;
        index  index.html index.htm;

        limit_access  zone=one;
    }

    location /limit_interface {
        limit_access_interface zone=one;
    }

    location /limit_status {
        limit_access_status zone=one;
    }
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_list=127.0.0.6,127.0.0.7,127.0.0.8,127.0.0.9,127.0.0.10"
--- response_body_like: ban list succeed

=== TEST 23: test the hash_table, try get
--- request 
GET /
--- response_body_like: .*

=== TEST 24: test the hash_table, add ip2
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_list=127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5"
--- response_body_like: ban list succeed

=== TEST 25: the following get test
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 26: test the hash_table, show list
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=all"
--- response_body_like
^(.*)key\[2\]: variable="127.0.0.10(.*)key\[2\]: variable="127.0.0.1(.*)

=== TEST 27: test the hash_table, ban 127.0.0.10 again with expires time 1s
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_list=127.0.0.10&ban_expire=0"
--- response_body_like: ban list succeed

=== TEST 28: test the hash_table, expire_list
--- request eval
"POST /limit_interface\n\n" . 
"expire_list"
--- response_body_like: Ban hash table expired

=== TEST 29: the following get test
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 30: test the hash_table, ban 127.0.0.1 again with expires time 1s
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=variable&ban_list=127.0.0.1&ban_expire=0"
--- response_body_like: ban list succeed

=== TEST 31: the following get test
--- request 
GET /
--- response_body_like: .*

=== TEST 32: test the hash_table, expire_list
--- request eval
"POST /limit_interface\n\n" . 
"expire_list"
--- response_body_like: Ban hash table expired

=== TEST 33: the following get test
--- request 
GET /
--- response_body_like: .*

