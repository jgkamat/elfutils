/* Find the split (or skeleton) unit for a given unit.
   Copyright (C) 2018 Red Hat, Inc.
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

#include "libdwP.h"
#include "libelfP.h"

#include <limits.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glob.h>

void
try_split_file (Dwarf_CU *cu, const char *dwo_path)
{
  int split_fd = open (dwo_path, O_RDONLY);
  if (split_fd != -1)
    {
      Dwarf *split_dwarf = dwarf_begin (split_fd, DWARF_C_READ);
      if (split_dwarf != NULL)
	{
		uint32_t info_offset = UINT32_MAX;
		uint32_t abbrev_offset = UINT32_MAX;
		uint32_t str_offset = UINT32_MAX;

		// Try to grab dwp sections
		if (split_dwarf->sectiondata[IDX_debug_cu_index] != NULL){
			uint32_t* header = (uint32_t*) split_dwarf->sectiondata[IDX_debug_cu_index]->d_buf;
			uint32_t dwp_version = header[0];
			uint32_t columns = header[1];
			uint32_t units = header[2];
			uint32_t slots = header[3];
			printf("DWP DEBUG: %d %d %d %d\n", dwp_version, columns, units, slots);

			uint64_t* hts = (uint64_t*)(split_dwarf->sectiondata[IDX_debug_cu_index]->d_buf + 16);
			uint64_t mask = (slots - 1);
			uint64_t hash = cu->unit_id8 & mask;
			uint64_t hash_prime = ((cu->unit_id8 >> 32) & mask) | 1;

			while (!(hts[hash] == 0x0 || hts[hash] == cu->unit_id8)) {
				// assert(hash < slots);
				hash = (hash + hash_prime) % slots;
			}
			if (hts[hash] == cu->unit_id8) {
				// found our gold!
				uint32_t* pti = (uint32_t*)(split_dwarf->sectiondata[IDX_debug_cu_index]->d_buf + 16 + 8 * slots);
				uint32_t row_index = pti[hash] - 1;
				printf("Match found in ht, index: %d\n", row_index);
				uint32_t* tso = (uint32_t*)(split_dwarf->sectiondata[IDX_debug_cu_index]->d_buf + 16 + 12 * slots);
				uint32_t* tss = tso + ((units + 1) * columns);

				// one additional slot to avoid having to index -1 all the time
				uint32_t sec_mapping[9];
				memset(sec_mapping, UINT32_MAX, sizeof(sec_mapping));
				for (uint32_t i = 0; i < columns; i++) {
					sec_mapping[tso[i]] = i;
				}
				// TODO make sure this isn't out of bounds;
				if (sec_mapping[DW_SECT_INFO] != UINT32_MAX
					&& sec_mapping[DW_SECT_ABBREV] != UINT32_MAX
					&& sec_mapping[DW_SECT_STR_OFFSETS] != UINT32_MAX){
					tso += columns * (row_index + 1);
					info_offset = tso[sec_mapping[DW_SECT_INFO]];
					abbrev_offset = tso[sec_mapping[DW_SECT_ABBREV]];
					str_offset = tso[sec_mapping[DW_SECT_STR_OFFSETS]];
					printf("Offsets: 0x%x, 0x%x, 0x%x\n", info_offset, abbrev_offset, str_offset);
					tss += columns * row_index;
					uint32_t info_size = tss[sec_mapping[DW_SECT_INFO]];
					uint32_t abbrev_size = tss[sec_mapping[DW_SECT_ABBREV]];
					// uint32_t str_size = tss[sec_mapping[DW_SECT_STR_OFFSETS]];
					printf("Sizes: 0x%x, 0x%x\n", info_size, abbrev_size);
				}
			}
		}

		if (abbrev_offset == UINT32_MAX)
			abbrev_offset = 0;
		if (str_offset == UINT32_MAX)
			str_offset = 0;

	  Dwarf_CU *split = NULL;
	  while (dwarf_get_units_adv (split_dwarf, split, &split,
				      NULL, NULL, NULL, NULL, abbrev_offset) == 0)
	    {

			split->str_off_base = str_offset;
			printf("Split: 0x%lx\n", split->unit_id8);
	      if (split->unit_type == DW_UT_split_compile
		  && cu->unit_id8 == split->unit_id8)
		{
		  if (tsearch (split->dbg, &cu->dbg->split_tree,
			       __libdw_finddbg_cb) == NULL)
		    {
		      /* Something went wrong.  Don't link.  */
		      __libdw_seterrno (DWARF_E_NOMEM);
		      break;
		    }

		  /* Link skeleton and split compile units.  */
		  __libdw_link_skel_split (cu, split);

		  /* We have everything we need from this ELF
		     file.  And we are going to close the fd to
		     not run out of file descriptors.  */
		  elf_cntl (split_dwarf->elf, ELF_C_FDDONE);
		  break;
		}
	    }
	  if (cu->split == (Dwarf_CU *) -1)
	    dwarf_end (split_dwarf);
	}
      /* Always close, because we don't want to run out of file
	 descriptors.  See also the elf_fcntl ELF_C_FDDONE call
	 above.  */
      close (split_fd);
    }
}

Dwarf_CU *
internal_function
__libdw_find_split_unit (Dwarf_CU *cu)
{
  /* Only try once.  */
  if (cu->split != (Dwarf_CU *) -1)
    return cu->split;

  /* We need a skeleton unit with a comp_dir and [GNU_]dwo_name attributes.
     The split unit will be the first in the dwo file and should have the
     same id as the skeleton.  */
  if (cu->unit_type == DW_UT_skeleton)
    {
      Dwarf_Die cudie = CUDIE (cu);
      Dwarf_Attribute dwo_name;
      /* It is fine if dwo_dir doesn't exists, but then dwo_name needs
	 to be an absolute path.  */
      if (dwarf_attr (&cudie, DW_AT_dwo_name, &dwo_name) != NULL
	  || dwarf_attr (&cudie, DW_AT_GNU_dwo_name, &dwo_name) != NULL)
	{
	  /* First try the dwo file name in the same directory
	     as we found the skeleton file.  */
	  const char *dwo_file = dwarf_formstring (&dwo_name);
	  const char *debugdir = cu->dbg->debugdir;
	  char *dwo_path = __libdw_filepath (debugdir, NULL, dwo_file);
	  if (dwo_path != NULL)
	    {
	      try_split_file (cu, dwo_path);
	      free (dwo_path);
	    }

	  if (cu->split == (Dwarf_CU *) -1) {
	    glob_t glob_result;
	    char dwpglob[PATH_MAX];
	    strcpy(dwpglob, debugdir);
	    strcat(dwpglob, "*.dwp");
	    int ret = glob(dwpglob, 0, NULL, &glob_result);

	    if(ret == 0) {
	      for(size_t i = 0; i < glob_result.gl_pathc; i++) {
		try_split_file (cu, glob_result.gl_pathv[i]);
	      }
	    }
	    globfree(&glob_result);
	  }


	  if (cu->split == (Dwarf_CU *) -1)
	    {
	      /* Try compdir plus dwo_name.  */
	      Dwarf_Attribute compdir;
	      dwarf_attr (&cudie, DW_AT_comp_dir, &compdir);
	      const char *dwo_dir = dwarf_formstring (&compdir);
	      if (dwo_dir != NULL)
		{
		  dwo_path = __libdw_filepath (debugdir, dwo_dir, dwo_file);
		  if (dwo_path != NULL)
		    {
		      try_split_file (cu, dwo_path);
		      free (dwo_path);
		    }
		}
	    }
	  /* XXX If still not found we could try stripping dirs from the
	     comp_dir and adding them from the comp_dir, assuming
	     someone moved a whole build tree around.  */
	}
    }

  /* If we found nothing, make sure we don't try again.  */
  if (cu->split == (Dwarf_CU *) -1)
    cu->split = NULL;

  return cu->split;
}
