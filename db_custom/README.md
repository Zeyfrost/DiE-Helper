# db_custom

Custom Detect It Easy signatures maintained by the DiE Helper fork.

- DiE loads this folder as the **custom database**. The default path is
  `$data/db_custom`, i.e. a `db_custom` folder next to `die.exe`. It can be
  changed (or enabled/disabled) in *Options -> Scan -> custom database*.
- Same subfolder layout as the official `db/`: `PE/`, `ELF/`, `MACH/`,
  `Binary/`, `MSDOS/`, ... A rule only runs for the file type of its folder.
- File naming: `<type>_<Name>.<prio>.sg`, for example
  `PE/packer_UPX_renamed_sections.2.sg`. `<type>` is the detection type
  (`packer`, `protector`, `compiler`, ...) and `<prio>` the priority used by
  the official DB for ordering.
- Rules run with the official DB's `_init` scripts (`meta()`, `result()`,
  `PE.section[]`, ...). **Never put an `_init` file here.**
- Updating the official database (the `dep/Detect-It-Easy` submodule / `db/`)
  never touches this folder, so custom rules survive DB updates.
