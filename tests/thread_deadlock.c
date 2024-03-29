/*
 * Copyright (C) 2017      Andreas Schneider <asn@samba.org>
 *
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
 *
 */

#include "config.h"

#include <stdio.h>
#include <signal.h>
#include <pthread.h>

#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
#define CONSTRUCTOR_ATTRIBUTE __attribute__ ((constructor))
#else
#define CONSTRUCTOR_ATTRIBUTE
#endif /* HAVE_CONSTRUCTOR_ATTRIBUTE */
#if ! defined(HAVE_CONSTRUCTOR_ATTRIBUTE) && defined(HAVE_PRAGMA_INIT)
/* xlC and other oldschool compilers support (only) this */
#pragma init (thread_deadlock_constructor)
#endif
void thread_deadlock_constructor(void) CONSTRUCTOR_ATTRIBUTE;

static void thread_deadlock_prepare(void)
{
	pthread_kill(pthread_self(), SIGUSR1);
	return;
}

static void thread_deadlock_parent(void)
{
	return;
}

static void thread_deadlock_child(void)
{
	return;
}

void thread_deadlock_constructor(void)
{
	pthread_atfork(&thread_deadlock_prepare,
		       &thread_deadlock_parent,
		       &thread_deadlock_child);
}
