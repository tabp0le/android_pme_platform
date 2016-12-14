/* Create new COMMON symbol.
   Copyright (C) 2002 Red Hat, Inc.
   This file is part of elfutils.
   Written by Ulrich Drepper <drepper@redhat.com>, 2002.

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libasmP.h>
#include <system.h>


static const AsmScn_t __libasm_com_scn =
  {
    .data = {
      .main = {
	.scn = ASM_COM_SCN
      }
    }
  };


AsmSym_t *
asm_newcomsym (ctx, name, size, align)
     AsmCtx_t *ctx;
     const char *name;
     GElf_Xword size;
     GElf_Addr align;
{
  AsmSym_t *result;

  if (ctx == NULL)
    
    return NULL;

  if (name == NULL)
    {
      __libasm_seterrno (ASM_E_INVALID);
      return NULL;
    }

  rwlock_wrlock (ctx->lock);

  result = (AsmSym_t *) malloc (sizeof (AsmSym_t));
  if (result == NULL)
    return NULL;

  result->scn = (AsmScn_t *) &__libasm_com_scn;
  result->size = size;
  
  result->type = STT_OBJECT;
  
  result->binding = STB_GLOBAL;
  result->symidx = 0;
  result->strent = ebl_strtabadd (ctx->symbol_strtab, name, 0);

  result->offset = align;

  if (unlikely (ctx->textp))
    fprintf (ctx->out.file, "\t.comm %s, %" PRIuMAX ", %" PRIuMAX "\n",
	     name, (uintmax_t) size, (uintmax_t) align);
  else
    {
      
      if (asm_symbol_tab_insert (&ctx->symbol_tab, elf_hash (name), result)
	  != 0)
	{
	  
	  __libasm_seterrno (ASM_E_DUPLSYM);
	  free (result);
	  result = NULL;
	}
      else if (name != NULL && asm_emit_symbol_p (name))
	
	++ctx->nsymbol_tab;
    }

  rwlock_unlock (ctx->lock);

  return result;
}
