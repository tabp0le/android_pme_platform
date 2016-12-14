/* Function return value location for Linux/TILE-Gx ABI.
   Copyright (C) 2012 Tilera Corporation
   Copyright (C) 2014 Red Hat, Inc.
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

#include <assert.h>
#include <dwarf.h>

#define BACKEND tilegx_
#include "libebl_CPU.h"


static const Dwarf_Op loc_intreg[] =
  {
    { .atom = DW_OP_reg0 }
  };
#define nloc_intreg	1

static const Dwarf_Op loc_aggregate[] =
  {
    { .atom = DW_OP_breg0, .number = 0 }
  };
#define nloc_aggregate 1

int
tilegx_return_value_location (Dwarf_Die *functypedie, const Dwarf_Op **locp)
{
  Dwarf_Die die_mem, *typedie = &die_mem;
  int tag = dwarf_peeled_die_type (functypedie, typedie);
  if (tag <= 0)
    return tag;

  Dwarf_Word size;
  switch (tag)
    {
    case -1:
      return -1;

    case DW_TAG_subrange_type:
      if (! dwarf_hasattr_integrate (typedie, DW_AT_byte_size))
	{
	  Dwarf_Attribute attr_mem, *attr;
	  attr = dwarf_attr_integrate (typedie, DW_AT_type, &attr_mem);
	  typedie = dwarf_formref_die (attr, &die_mem);
	  tag = DWARF_TAG_OR_RETURN (typedie);
	}
      

    case DW_TAG_base_type:
    case DW_TAG_enumeration_type:
    case DW_TAG_pointer_type:
    case DW_TAG_ptr_to_member_type:
      {
	Dwarf_Attribute attr_mem;
	if (dwarf_formudata (dwarf_attr_integrate (typedie, DW_AT_byte_size,
						   &attr_mem), &size) != 0)
	  {
	    if (tag == DW_TAG_pointer_type || tag == DW_TAG_ptr_to_member_type)
	      size = 8;
	    else
	      return -1;
	  }
	if (tag == DW_TAG_base_type)
	  {
	    Dwarf_Word encoding;
	    if (dwarf_formudata (dwarf_attr_integrate (typedie, DW_AT_encoding,
						       &attr_mem),
				 &encoding) != 0)
	      return -1;
	  }
      }

      
      if (size <= 8)
	{
	intreg:
	  *locp = loc_intreg;
	  return nloc_intreg;
	}

      
    case DW_TAG_structure_type:
    case DW_TAG_class_type:
    case DW_TAG_union_type:
    aggregate:
      *locp = loc_aggregate;
      return nloc_aggregate;

    case DW_TAG_array_type:
    case DW_TAG_string_type:
      if (dwarf_aggregate_size (typedie, &size) == 0 && size <= 8)
	{
	  if (tag == DW_TAG_array_type)
	    {
	      Dwarf_Attribute attr_mem, *attr;
	      
	      attr = dwarf_attr_integrate (typedie, DW_AT_type, &attr_mem);
	      typedie = dwarf_formref_die (attr, &die_mem);
	      tag = DWARF_TAG_OR_RETURN (typedie);
	      if (tag != DW_TAG_base_type)
		goto aggregate;
	      if (dwarf_formudata (dwarf_attr_integrate (typedie,
							 DW_AT_byte_size,
							 &attr_mem),
				   &size) != 0)
		return -1;
	      if (size != 1)
		goto aggregate;
	    }
	  goto intreg;
	}
      goto aggregate;
    }

  return -2;
}
