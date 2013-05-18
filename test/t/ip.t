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
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
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
"ban_type=ip&ban_list=127.0.0.1,127.1.1.1"
--- response_body_like: ban list succeed

=== TEST 3: the following get test
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 4: the free_list test
--- request eval
"POST /limit_interface\n\n" . 
"free_type=ip&free_list=127.0.0.1,127.1.1.1"
--- response_body_like: free list succeed with 2 records

=== TEST 5: the following get test
--- request 
GET /
--- response_body_like: .*

=== TEST 6: the ban_list test again
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=ip&ban_list=2130706433,2130772225"
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
"show_type=ip&show_list=2130706433"
--- response_body_like: ^Ban hash table:(.*)ip(.*)$

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
"show_type=ip&show_list=all"
--- response_body_like: ^Ban hash table:(.*)total record = 0$

=== TEST 14: the show_list test, wrong type
--- request eval
"POST /limit_interface\n\n" . 
"show_type=variable&show_list=all"
--- error_code: 400
--- response_body_like: ^.*$

=== TEST 15: the show_list test, set the output buffer size
--- http_config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
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
"show_type=ip&show_list=all"
--- response_body_like: ^Ban hash table:(.*)total record = 0$

=== TEST 16: the hash table test, set the bucket number to be 3
--- http_config
limit_access_zone  zone=one:5m bucket_number=3 type=ip;
--- config
    limit_access_variable zone=one $limit_access_deny;
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
"ban_type=ip&ban_list=127.0.0.1,127.0.0.4"
--- response_body_like: ban list succeed

=== TEST 17: the hash table test, show 127.0.0.4
--- request eval
"POST /limit_interface\n\n" . 
"show_type=ip&show_list=127.0.0.4"
--- response_body_like: (.*)127.0.0.4(.*)

=== TEST 18: the hash table test, delete 127.0.0.1
--- request eval
"POST /limit_interface\n\n" . 
"free_type=ip&free_list=127.0.0.1"
--- response_body
free list succeed with 1 records

=== TEST 19: the hash table test, show 127.0.0.4
--- request eval
"POST /limit_interface\n\n" . 
"show_type=ip&show_list=127.0.0.4"
--- response_body_like: (.*)127.0.0.4(.*)expire

=== TEST 20: the hash table test, set the bucket number to be 3, default expires 1s
--- http_config
limit_access_zone  zone=one:5m bucket_number=3 type=ip;
--- config
    limit_access_variable zone=one $limit_access_deny;
     limit_access_default_expire 1s;
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
"ban_type=ip&ban_list=127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5"
--- response_body_like: ban list succeed

=== TEST 21: the following get test
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 22: add more ip
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=ip&ban_list=127.0.0.6,127.0.0.7,127.0.0.8,127.0.0.9,127.0.0.10&ban_expire=1d"
--- response_body_like: ban list succeed

=== TEST 23: the show_list
--- request eval
"POST /limit_interface\n\n" . 
"show_type=ip&show_list=all"
--- response_body_like
^(.*)key\[2\]: ip=127.0.0.1(.*)key\[2\]: ip=127.0.0.10(.*)

=== TEST 24: the expire_list
--- request eval
"POST /limit_interface\n\n" . 
"expire_list"
--- response_body_like: Ban hash table expired.

=== TEST 25: add the ip again
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=ip&ban_list=127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5"
--- response_body_like: ban list succeed

=== TEST 26: the show_list
--- request eval
"POST /limit_interface\n\n" . 
"show_type=ip&show_list=all"
--- response_body_like
^(.*)key\[2\]: ip=127.0.0.1(.*)key\[2\]: ip=127.0.0.10(.*)
