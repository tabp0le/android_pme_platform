/* Return section header.
   Copyright (C) 1998-2002, 2005, 2007, 2009, 2012, 2014 Red Hat, Inc.
   This file is part of elfutils.
   Written by Ulrich Drepper <drepper@redhat.com>, 1998.

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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#include <system.h>
#include "libelfP.h"
#include "common.h"

#ifndef LIBELFBITS
# define LIBELFBITS 32
#endif


static ElfW2(LIBELFBITS,Shdr) *
load_shdr_wrlock (Elf_Scn *scn)
{
  ElfW2(LIBELFBITS,Shdr) *result;

  
  Elf *elf = scn->elf;
  ElfW2(LIBELFBITS,Ehdr) *ehdr = elf->state.ELFW(elf,LIBELFBITS).ehdr;

  
  result = scn->shdr.ELFW(e,LIBELFBITS);
  if (result != NULL)
    goto out;

  size_t shnum;
  if (__elf_getshdrnum_rdlock (elf, &shnum) != 0
      || shnum > SIZE_MAX / sizeof (ElfW2(LIBELFBITS,Shdr)))
    goto out;
  size_t size = shnum * sizeof (ElfW2(LIBELFBITS,Shdr));

  ElfW2(LIBELFBITS,Shdr) *shdr = elf->state.ELFW(elf,LIBELFBITS).shdr =
    (ElfW2(LIBELFBITS,Shdr) *) malloc (size);
  if (elf->state.ELFW(elf,LIBELFBITS).shdr == NULL)
    {
      __libelf_seterrno (ELF_E_NOMEM);
      goto out;
    }
  elf->state.ELFW(elf,LIBELFBITS).shdr_malloced = 1;

  if (elf->map_address != NULL)
    {
      if (unlikely (ehdr->e_shoff >= elf->maximum_size)
	  || unlikely (elf->maximum_size - ehdr->e_shoff < size))
	{
	  
	  __libelf_seterrno (ELF_E_INVALID_SECTION_HEADER);
	  goto free_and_out;
	}

      ElfW2(LIBELFBITS,Shdr) *notcvt;

      void *file_shdr = ((char *) elf->map_address
			 + elf->start_offset + ehdr->e_shoff);

      assert ((elf->flags & ELF_F_MALLOCED)
	      || ehdr->e_ident[EI_DATA] != MY_ELFDATA
	      || (! ALLOW_UNALIGNED
		  && ((uintptr_t) file_shdr
		      & (__alignof__ (ElfW2(LIBELFBITS,Shdr)) - 1)) != 0));

      
      if (ehdr->e_ident[EI_DATA] == MY_ELFDATA)
	{
	  assert ((elf->flags & ELF_F_MALLOCED) || ! ALLOW_UNALIGNED);
	  memcpy (shdr, file_shdr, size);
	}
      else
	{
	  if (ALLOW_UNALIGNED
	      || ((uintptr_t) file_shdr
		  & (__alignof__ (ElfW2(LIBELFBITS,Shdr)) - 1)) == 0)
	    notcvt = (ElfW2(LIBELFBITS,Shdr) *)
	      ((char *) elf->map_address
	       + elf->start_offset + ehdr->e_shoff);
	  else
	    {
	      notcvt = (ElfW2(LIBELFBITS,Shdr) *) alloca (size);
	      memcpy (notcvt, ((char *) elf->map_address
			       + elf->start_offset + ehdr->e_shoff),
		      size);
	    }

	  for (size_t cnt = 0; cnt < shnum; ++cnt)
	    {
	      CONVERT_TO (shdr[cnt].sh_name, notcvt[cnt].sh_name);
	      CONVERT_TO (shdr[cnt].sh_type, notcvt[cnt].sh_type);
	      CONVERT_TO (shdr[cnt].sh_flags, notcvt[cnt].sh_flags);
	      CONVERT_TO (shdr[cnt].sh_addr, notcvt[cnt].sh_addr);
	      CONVERT_TO (shdr[cnt].sh_offset, notcvt[cnt].sh_offset);
	      CONVERT_TO (shdr[cnt].sh_size, notcvt[cnt].sh_size);
	      CONVERT_TO (shdr[cnt].sh_link, notcvt[cnt].sh_link);
	      CONVERT_TO (shdr[cnt].sh_info, notcvt[cnt].sh_info);
	      CONVERT_TO (shdr[cnt].sh_addralign,
			  notcvt[cnt].sh_addralign);
	      CONVERT_TO (shdr[cnt].sh_entsize, notcvt[cnt].sh_entsize);

	      if (shdr[cnt].sh_type == SHT_SYMTAB_SHNDX
		  && shdr[cnt].sh_link < shnum)
		elf->state.ELFW(elf,LIBELFBITS).scns.data[shdr[cnt].sh_link].shndx_index
		  = cnt;

	      if (elf->state.ELFW(elf,LIBELFBITS).scns.data[cnt].shndx_index == 0)
		elf->state.ELFW(elf,LIBELFBITS).scns.data[cnt].shndx_index
		  = -1;
	    }
	}
    }
  else if (likely (elf->fildes != -1))
    {
      
      ssize_t n = pread_retry (elf->fildes,
			       elf->state.ELFW(elf,LIBELFBITS).shdr, size,
			       elf->start_offset + ehdr->e_shoff);
      if (unlikely ((size_t) n != size))
	{
	  
	  __libelf_seterrno (ELF_E_READ_ERROR);
	  goto free_and_out;
	}

      if (ehdr->e_ident[EI_DATA] != MY_ELFDATA)
	for (size_t cnt = 0; cnt < shnum; ++cnt)
	  {
	    CONVERT (shdr[cnt].sh_name);
	    CONVERT (shdr[cnt].sh_type);
	    CONVERT (shdr[cnt].sh_flags);
	    CONVERT (shdr[cnt].sh_addr);
	    CONVERT (shdr[cnt].sh_offset);
	    CONVERT (shdr[cnt].sh_size);
	    CONVERT (shdr[cnt].sh_link);
	    CONVERT (shdr[cnt].sh_info);
	    CONVERT (shdr[cnt].sh_addralign);
	    CONVERT (shdr[cnt].sh_entsize);
	  }
    }
  else
    {
      __libelf_seterrno (ELF_E_FD_DISABLED);

    free_and_out:
      free (shdr);
      elf->state.ELFW(elf,LIBELFBITS).shdr = NULL;
      elf->state.ELFW(elf,LIBELFBITS).shdr_malloced = 0;

      goto out;
    }

  
  for (size_t cnt = 0; cnt < shnum; ++cnt)
    elf->state.ELFW(elf,LIBELFBITS).scns.data[cnt].shdr.ELFW(e,LIBELFBITS)
      = &elf->state.ELFW(elf,LIBELFBITS).shdr[cnt];

  result = scn->shdr.ELFW(e,LIBELFBITS);
  assert (result != NULL);

out:
  return result;
}

static bool
scn_valid (Elf_Scn *scn)
{
  if (scn == NULL)
    return false;

  if (unlikely (scn->elf->state.elf.ehdr == NULL))
    {
      __libelf_seterrno (ELF_E_WRONG_ORDER_EHDR);
      return false;
    }

  if (unlikely (scn->elf->class != ELFW(ELFCLASS,LIBELFBITS)))
    {
      __libelf_seterrno (ELF_E_INVALID_CLASS);
      return false;
    }

  return true;
}

ElfW2(LIBELFBITS,Shdr) *
__elfw2(LIBELFBITS,getshdr_rdlock) (scn)
     Elf_Scn *scn;
{
  ElfW2(LIBELFBITS,Shdr) *result;

  if (!scn_valid (scn))
    return NULL;

  result = scn->shdr.ELFW(e,LIBELFBITS);
  if (result == NULL)
    {
      rwlock_unlock (scn->elf->lock);
      rwlock_wrlock (scn->elf->lock);
      result = scn->shdr.ELFW(e,LIBELFBITS);
      if (result == NULL)
	result = load_shdr_wrlock (scn);
    }

  return result;
}

ElfW2(LIBELFBITS,Shdr) *
__elfw2(LIBELFBITS,getshdr_wrlock) (scn)
     Elf_Scn *scn;
{
  ElfW2(LIBELFBITS,Shdr) *result;

  if (!scn_valid (scn))
    return NULL;

  result = scn->shdr.ELFW(e,LIBELFBITS);
  if (result == NULL)
    result = load_shdr_wrlock (scn);

  return result;
}

ElfW2(LIBELFBITS,Shdr) *
elfw2(LIBELFBITS,getshdr) (scn)
     Elf_Scn *scn;
{
  ElfW2(LIBELFBITS,Shdr) *result;

  if (!scn_valid (scn))
    return NULL;

  rwlock_rdlock (scn->elf->lock);
  result = __elfw2(LIBELFBITS,getshdr_rdlock) (scn);
  rwlock_unlock (scn->elf->lock);

  return result;
}
