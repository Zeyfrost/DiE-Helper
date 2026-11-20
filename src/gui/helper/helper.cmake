# DiE Helper (fork addition): sources and data of the Helper panel.
# Included from src/gui/diegui.cmake.
#
# No include_directories() here on purpose: it would change the compile command of every file in
# the die target and force a near-full rebuild. src/gui is already on the include path, so the
# rest of the GUI includes these headers as "helper/xxx.h".

set(HELPER_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/helperevidence.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperevidence.h
    ${CMAKE_CURRENT_LIST_DIR}/helperpackingview.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperpackingview.h
    ${CMAKE_CURRENT_LIST_DIR}/helpersectionmap.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helpersectionmap.h
    ${CMAKE_CURRENT_LIST_DIR}/helperactions.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperactions.h
    ${CMAKE_CURRENT_LIST_DIR}/helperstrings.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperstrings.h
    ${CMAKE_CURRENT_LIST_DIR}/helperapihash.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperapihash.h
    ${CMAKE_CURRENT_LIST_DIR}/helpernetinfo.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helpernetinfo.h
    ${CMAKE_CURRENT_LIST_DIR}/helperdecompressor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperdecompressor.h
    ${CMAKE_CURRENT_LIST_DIR}/helperrebuild.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperrebuild.h
    ${CMAKE_CURRENT_LIST_DIR}/helperoepfinder.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperoepfinder.h
    ${CMAKE_CURRENT_LIST_DIR}/helperreport.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperreport.h
    ${CMAKE_CURRENT_LIST_DIR}/helpersignaturemaker.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helpersignaturemaker.h
    ${CMAKE_CURRENT_LIST_DIR}/helperbatch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperbatch.h
    ${CMAKE_CURRENT_LIST_DIR}/helperupx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperupx.h
    ${CMAKE_CURRENT_LIST_DIR}/helperunpacker.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperunpacker.h
    ${CMAKE_CURRENT_LIST_DIR}/helperpesurgery.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperpesurgery.h
    ${CMAKE_CURRENT_LIST_DIR}/helperverdict.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperverdict.h
    ${CMAKE_CURRENT_LIST_DIR}/helperhints.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperhints.h
    ${CMAKE_CURRENT_LIST_DIR}/helperoptionswidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helperoptionswidget.h
    ${CMAKE_CURRENT_LIST_DIR}/helpersettings.cpp
    ${CMAKE_CURRENT_LIST_DIR}/helpersettings.h
)

# hints.json lives at the repo top level (helper/), next to db_custom/, outside every submodule.
# Installed as $data/helper/hints.json (= <exe dir>/helper/hints.json on Windows).
if(DEFINED X_RESOURCES)
    install(FILES "${CMAKE_SOURCE_DIR}/helper/hints.json" DESTINATION "${X_RESOURCES}/helper" OPTIONAL)
    # The user's own signatures: top-level db_custom/ -> $data/db_custom, which is DiE's default
    # custom database path (Options -> Scan). Installed after the submodule's db_custom, same folder;
    # nothing here is ever overwritten by replacing the official db/.
    install(DIRECTORY "${CMAKE_SOURCE_DIR}/db_custom/" DESTINATION "${X_RESOURCES}/db_custom" OPTIONAL
            PATTERN "README.md" EXCLUDE)
endif()
