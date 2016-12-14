

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

#ifndef __PUB_CORE_CLREQ_H
#define __PUB_CORE_CLREQ_H


#include "pub_tool_clreq.h"

typedef
   enum { 
      
      VG_USERREQ__LIBC_FREERES_DONE = 0x3029,

      
      VG_USERREQ__GET_MALLOCFUNCS   = 0x3030,

      
      VG_USERREQ__INTERNAL_PRINTF_VALIST_BY_REF = 0x3103,

      
      VG_USERREQ__ADD_IFUNC_TARGET  = 0x3104,

   } Vg_InternalClientRequest;


static int VALGRIND_INTERNAL_PRINTF(const char *format, ...)
   __attribute__((format(__printf__, 1, 2), __unused__));
static int VALGRIND_INTERNAL_PRINTF(const char *format, ...)
{
   unsigned long _qzz_res = 0;
   va_list vargs;
   va_start(vargs, format);
   VALGRIND_DO_CLIENT_REQUEST(
      _qzz_res, 0, VG_USERREQ__INTERNAL_PRINTF_VALIST_BY_REF,
      (unsigned long)format, (unsigned long)&vargs, 0, 0, 0
   );
   va_end(vargs);
   return _qzz_res;
}


#endif   

