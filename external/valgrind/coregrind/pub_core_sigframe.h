

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2013 Julian Seward
      jseward@acm.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef __PUB_CORE_SIGFRAME_H
#define __PUB_CORE_SIGFRAME_H

#include "pub_core_basics.h"     
#include "pub_core_vki.h"        


extern 
void VG_(sigframe_create) ( ThreadId tid, 
                            Addr sp_top_of_frame,
                            const vki_siginfo_t *siginfo,
                            const struct vki_ucontext *uc,
                            void *handler, 
                            UInt flags,
                            const vki_sigset_t *mask,
                            void *restorer );

extern 
void VG_(sigframe_destroy)( ThreadId tid, Bool isRT );

#endif   

