/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2005-2008, Jelmer Vernooij <jelmer@samba.org>
 * Copyright (c) 2006-2021, Stefan Metzmacher <metze@samba.org>
 * Copyright (c) 2013-2021, Andreas Schneider <asn@samba.org>
 * Copyright (c) 2014-2017, Michael Adam <obnox@samba.org>
 * Copyright (c) 2016-2018, Anoop C S <anoopcs@redhat.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
   Socket wrapper noop library.

   Applications with the need to alter their behaviour when
   socket wrapper is active, can link to this with -lsocket_wrapper_noop
   in order to call get the required public functions at link time.

   During runtime these are overloaded with LD_PRELOAD by the real
   libsocket_wrapper.so.
*/

#include "config.h"
#include "stdbool.h"
#include "socket_wrapper.h"

bool socket_wrapper_enabled(void)
{
	return false;
}

void socket_wrapper_indicate_no_inet_fd(int fd)
{
	(void) fd; /* unused */
	return;
}
