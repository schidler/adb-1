/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sysdeps.h"
#include <sys/types.h>

#define  TRACE_TAG  TRACE_TRANSPORT
#include "adb.h"


#define fix_endians(p) do {} while (0)



/* we keep a list of opened transports, transport 0 is bound to 5555,
 * transport 1 to 5557, .. transport n to 5555 + n*2. the list is used
 * to detect when we're trying to connect twice to a given local transport
 */
#define  ADB_LOCAL_TRANSPORT_MAX  16

ADB_MUTEX_DEFINE( local_transports_lock );

static atransport*  local_transports[ ADB_LOCAL_TRANSPORT_MAX ];


static int remote_read(apacket *p, atransport *t)
{
    if(readx(t->sfd, &p->msg, sizeof(amessage))){
        D("remote local: read terminated (message)\n");
        return -1;
    }

    fix_endians(p);


    if(check_header(p)) {
        D("bad header: terminated (data)\n");
        return -1;
    }

    if(readx(t->sfd, p->data, p->msg.data_length)){
        D("remote local: terminated (data)\n");
        return -1;
    }

    if(check_data(p)) {
        D("bad data: terminated (data)\n");
        return -1;
    }

    return 0;
}

static int remote_write(apacket *p, atransport *t)
{
    int   length = p->msg.data_length;

    fix_endians(p);


    if(writex(t->sfd, &p->msg, sizeof(amessage) + length)) {
        D("remote local: write terminated\n");
        return -1;
    }

    return 0;
}


int  local_connect(int  port)
{
    char buf[64];
    int  fd = -1;


    const char *host = getenv("ADBHOST");
    if (host) {
        fd = socket_network_client(host, port, SOCK_STREAM);
    }

    if (fd < 0) {
        fd = socket_loopback_client(port, SOCK_STREAM);
    }

    if (fd >= 0) {
        D("client: connected on remote on fd %d\n", fd);
        close_on_exec(fd);
        disable_tcp_nagle(fd);
        snprintf(buf, sizeof buf, "%s%d", LOCAL_CLIENT_PREFIX, port - 1);
        register_socket_transport(fd, buf, port, 1);
        return 0;
    }
    return -1;
}


static void *client_socket_thread(void *x)
{

    int  port  = ADB_LOCAL_TRANSPORT_PORT;
    int  count = ADB_LOCAL_TRANSPORT_MAX;

    D("transport: client_socket_thread() starting\n");

    /* try to connect to any number of running emulator instances     */
    /* this is only done when ADB starts up. later, each new emulator */
    /* will send a message to ADB to indicate that is is starting up  */
    for ( ; count > 0; count--, port += 2 ) {
        (void) local_connect(port);
    }

    return 0;
}

static void *server_socket_thread(void * arg)
{
    int serverfd, fd;
    struct sockaddr addr;
    socklen_t alen;
    int port = (int)arg;

    D("transport: server_socket_thread() starting\n");
    serverfd = -1;
    for(;;) {
        if(serverfd == -1) {
            serverfd = socket_inaddr_any_server(port, SOCK_STREAM);
            if(serverfd < 0) {
                D("server: cannot bind socket yet\n");
                adb_sleep_ms(1000);
                continue;
            }
            close_on_exec(serverfd);
        }

        alen = sizeof(addr);
        D("server: trying to get new connection from %d\n", port);
        fd = adb_socket_accept(serverfd, &addr, &alen);
        if(fd >= 0) {
            D("server: new connection on fd %d\n", fd);
            close_on_exec(fd);
            disable_tcp_nagle(fd);
            register_socket_transport(fd, "host", port, 1);
        }
    }
    D("transport: server_socket_thread() exiting\n");
    return 0;
}

void local_init(int port)
{
    adb_thread_t thr;
    void* (*func)(void *);

    if(HOST) {
        func = client_socket_thread;
    } else {
        func = server_socket_thread;
    }

    D("transport: local %s init\n", HOST ? "client" : "server");

    if(adb_thread_create(&thr, func, (void *)port)) {
        fatal_errno("cannot create local socket %s thread",
                    HOST ? "client" : "server");
    }
}

static void remote_kick(atransport *t)
{
    int fd = t->sfd;
    t->sfd = -1;
    adb_shutdown(fd);
    adb_close(fd);


    if(HOST) {
        int  nn;
        adb_mutex_lock( &local_transports_lock );
        for (nn = 0; nn < ADB_LOCAL_TRANSPORT_MAX; nn++) {
            if (local_transports[nn] == t) {
                local_transports[nn] = NULL;
                break;
            }
        }
        adb_mutex_unlock( &local_transports_lock );
    }

}

static void remote_close(atransport *t)
{
    adb_close(t->fd);
}

int init_socket_transport(atransport *t, int s, int port, int local)
{
    int  fail = 0;

    t->kick = remote_kick;
    t->close = remote_close;
    t->read_from_remote = remote_read;
    t->write_to_remote = remote_write;
    t->sfd = s;
    t->sync_token = 1;
    t->connection_state = CS_OFFLINE;
    t->type = kTransportLocal;


    if (HOST && local) {
        adb_mutex_lock( &local_transports_lock );
        {
            int  index = (port - ADB_LOCAL_TRANSPORT_PORT)/2;

            if (!(port & 1) || index < 0 || index >= ADB_LOCAL_TRANSPORT_MAX) {
                D("bad local transport port number: %d\n", port);
                fail = -1;
            }
            else if (local_transports[index] != NULL) {
                D("local transport for port %d already registered (%p)?\n",
                port, local_transports[index]);
                fail = -1;
            }
            else
                local_transports[index] = t;
        }
        adb_mutex_unlock( &local_transports_lock );
    }

    return fail;
}
