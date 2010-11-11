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

run_tests();

__DATA__

=== TEST 1: the get test
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request 
GET /
--- response_body_like: .*


=== TEST 2: the ban_list test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=ip&ban_list=127.0.0.1,127.1.1.1"
--- response_body_like: ban list succeed

=== TEST 3: the following get test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 4: the free_list test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request eval
"POST /limit_interface\n\n" . 
"free_type=ip&free_list=127.0.0.1,127.1.1.1"
--- response_body_like: free list succeed

=== TEST 5: the following get test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request 
GET /
--- response_body_like: .*

=== TEST 6: the ban_list test again
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request eval
"POST /limit_interface\n\n" . 
"ban_type=ip&ban_list=2130706433,2130772225"
--- response_body_like: ban list succeed

=== TEST 7: the following get test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 8: the expire_list test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request eval
"POST /limit_interface\n\n" . 
"expire_list"
--- response_body_like: Ban hash table expired.

=== TEST 9: the following get test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request 
GET /
--- error_code: 403
--- response_body_like: .*

=== TEST 10: the show_list test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request eval
"POST /limit_interface\n\n" . 
"show_type=ip&show_list=2130706433"
--- response_body_like: ^Ban hash table:(.*)ip(.*)$

=== TEST 11: the destroy_list test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request eval
"POST /limit_interface\n\n" . 
"destroy_list"
--- response_body_like: Ban hash table destroyed.

=== TEST 12: the following get test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request 
GET /
--- response_body_like: .*

=== TEST 13: the show_list test
--- no_manager
--- config
limit_access_zone  zone=one:5m bucket_number=10007 type=ip;
server {
    listen       1982;
    server_name  localhost;

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
}
--- request eval
"POST /limit_interface\n\n" . 
"show_type=ip&show_list=all"
--- response_body_like: ^Ban hash table:(.*)total record = 0$

