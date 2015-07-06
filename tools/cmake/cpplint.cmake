# This file contains functions and configurations for generating PC-Lint build
# targets for your CMake projects.

set(CPPLINT_EXECUTABLE "python")
set(CPPLINT_EXECUTABLE2 "${PROJECT_SOURCE_DIR}/tools/cmake/cpplint.py")
add_custom_target(ALL_CPPLINT)

function(add_cpplint target)
    get_directory_property(cpplint_include_directories INCLUDE_DIRECTORIES)
    get_directory_property(cpplint_defines COMPILE_DEFINITIONS)

    # let's get those elephants across the alps
    # prepend each include directory with "-i"; also quotes the directory
    set(cpplint_include_directories_transformed)
    foreach(include_dir ${cpplint_include_directories})
        list(APPEND cpplint_include_directories_transformed -i"${include_dir}")
    endforeach(include_dir)

    # prepend each definition with "-d"
    set(cpplint_defines_transformed)
    foreach(definition ${cpplint_defines})
        list(APPEND cpplint_defines_transformed -d${definition})
    endforeach(definition)
        
    # list of all commands, one for each given source file
    set(cpplint_commands)

    foreach(sourcefile ${ARGN})
        # only include c and cpp files
        if( sourcefile MATCHES \\.c$|\\.cxx$|\\.cpp$ )
            # make filename absolute
            get_filename_component(sourcefile_abs ${sourcefile} ABSOLUTE)
            # create command line for linting one source file and add it to the list of commands
            list(APPEND cpplint_commands
                COMMAND ${CPPLINT_EXECUTABLE} ${CPPLINT_EXECUTABLE2}
                ${lint_include_directories_transformed}
                ${lint_defines_transformed}
                ${sourcefile_abs})
        endif()
    endforeach(sourcefile)

    # add a custom target consisting of all the commands generated above
    add_custom_target(${target}_CPPLINT ${cpplint_commands} VERBATIM)
    # make the ALL_LINT target depend on each and every *_LINT target
    add_dependencies(ALL_CPPLINT ${target}_CPPLINT)

endfunction(add_cpplint)
