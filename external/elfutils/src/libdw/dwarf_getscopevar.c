/* Find a named variable or parameter within given scopes.
   Copyright (C) 2005-2009 Red Hat, Inc.
   This file is part of elfutils.

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

#include <stdbool.h>
#include <string.h>
#include "libdwP.h"
#include <dwarf.h>


static int
getfiles (Dwarf_Die *die, Dwarf_Files **files)
{
  return INTUSE(dwarf_getsrcfiles) (&CUDIE (die->cu), files, NULL);
}

static int
getattr (Dwarf_Die *die, int search_name, Dwarf_Word *value)
{
  Dwarf_Attribute attr_mem;
  return INTUSE(dwarf_formudata) (INTUSE(dwarf_attr) (die, search_name,
						      &attr_mem), value);
}


int
dwarf_getscopevar (Dwarf_Die *scopes, int nscopes,
		   const char *name, int skip_shadows,
		   const char *match_file, int match_lineno, int match_linecol,
		   Dwarf_Die *result)
{
  
  size_t match_file_len = match_file == NULL ? 0 : strlen (match_file);
  bool lastfile_matches = false;
  const char *lastfile = NULL;
  inline bool file_matches (Dwarf_Files *files, size_t idx)
    {
      if (idx >= files->nfiles)
	return false;

      const char *file = files->info[idx].name;
      if (file != lastfile)
	{
	  size_t len = strlen (file);
	  lastfile_matches = (len >= match_file_len
			      && !memcmp (match_file, file, match_file_len)
			      && (len == match_file_len
				  || file[len - match_file_len - 1] == '/'));
	}
      return lastfile_matches;
    }

  
  for (int out = 0; out < nscopes; ++out)
    if (INTUSE(dwarf_haschildren) (&scopes[out]))
      {
	if (INTUSE(dwarf_child) (&scopes[out], result) != 0)
	  return -1;
	do
	  {
	    switch (INTUSE(dwarf_tag) (result))
	      {
	      case DW_TAG_variable:
	      case DW_TAG_formal_parameter:
		break;

	      default:
		continue;
	      }

	    
	    const char *diename = INTUSE(dwarf_diename) (result);
	    if (diename != NULL && !strcmp (name, diename))
	      {
		

		if (skip_shadows > 0)
		  {
		    
		    --skip_shadows;
		    break;
		  }

		if (match_file != NULL)
		  {
		    

		    Dwarf_Word i;
		    Dwarf_Files *files;
		    if (getattr (result, DW_AT_decl_file, &i) != 0
			|| getfiles (&scopes[out], &files) != 0)
		      break;

		    if (!file_matches (files, i))
		      break;

		    if (match_lineno > 0
			&& (getattr (result, DW_AT_decl_line, &i) != 0
			    || (int) i != match_lineno))
		      break;
		    if (match_linecol > 0
			&& (getattr (result, DW_AT_decl_column, &i) != 0
			    || (int) i != match_linecol))
		      break;
		  }

		
		return out;
	      }
	  }
	while (INTUSE(dwarf_siblingof) (result, result) == 0);
      }

  return -2;
}
