# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/itsp/semin/ccs22

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/itsp/semin/ccs22

# Include any dependencies generated for this target.
include libsnark/CMakeFiles/profile_routing_algorithms.dir/depend.make

# Include the progress variables for this target.
include libsnark/CMakeFiles/profile_routing_algorithms.dir/progress.make

# Include the compile flags for this target's objects.
include libsnark/CMakeFiles/profile_routing_algorithms.dir/flags.make

libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o: libsnark/CMakeFiles/profile_routing_algorithms.dir/flags.make
libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o: libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/itsp/semin/ccs22/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o"
	cd /home/itsp/semin/ccs22/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o -c /home/itsp/semin/ccs22/libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp

libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.i"
	cd /home/itsp/semin/ccs22/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/itsp/semin/ccs22/libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp > CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.i

libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.s"
	cd /home/itsp/semin/ccs22/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/itsp/semin/ccs22/libsnark/common/routing_algorithms/profiling/profile_routing_algorithms.cpp -o CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.s

# Object files for target profile_routing_algorithms
profile_routing_algorithms_OBJECTS = \
"CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o"

# External object files for target profile_routing_algorithms
profile_routing_algorithms_EXTERNAL_OBJECTS =

libsnark/profile_routing_algorithms: libsnark/CMakeFiles/profile_routing_algorithms.dir/common/routing_algorithms/profiling/profile_routing_algorithms.cpp.o
libsnark/profile_routing_algorithms: libsnark/CMakeFiles/profile_routing_algorithms.dir/build.make
libsnark/profile_routing_algorithms: libsnark/libsnark.a
libsnark/profile_routing_algorithms: depends/libff/libff/libff.a
libsnark/profile_routing_algorithms: /usr/bin/libgmp.so
libsnark/profile_routing_algorithms: /usr/lib/x86_64-linux-gnu/libsodium.so
libsnark/profile_routing_algorithms: /usr/bin/libgmp.so
libsnark/profile_routing_algorithms: /usr/lib/x86_64-linux-gnu/libgmpxx.so
libsnark/profile_routing_algorithms: libsnark/CMakeFiles/profile_routing_algorithms.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/itsp/semin/ccs22/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable profile_routing_algorithms"
	cd /home/itsp/semin/ccs22/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profile_routing_algorithms.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libsnark/CMakeFiles/profile_routing_algorithms.dir/build: libsnark/profile_routing_algorithms

.PHONY : libsnark/CMakeFiles/profile_routing_algorithms.dir/build

libsnark/CMakeFiles/profile_routing_algorithms.dir/clean:
	cd /home/itsp/semin/ccs22/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/profile_routing_algorithms.dir/cmake_clean.cmake
.PHONY : libsnark/CMakeFiles/profile_routing_algorithms.dir/clean

libsnark/CMakeFiles/profile_routing_algorithms.dir/depend:
	cd /home/itsp/semin/ccs22 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/itsp/semin/ccs22 /home/itsp/semin/ccs22/libsnark /home/itsp/semin/ccs22 /home/itsp/semin/ccs22/libsnark /home/itsp/semin/ccs22/libsnark/CMakeFiles/profile_routing_algorithms.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/CMakeFiles/profile_routing_algorithms.dir/depend

