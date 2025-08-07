cmake_minimum_required(VERSION 3.18)
project(kss16core LANGUAGES C CXX)

# ---- 0. 全局禁用 mcl 汇编（必须放在 add_subdirectory 之前） ----
add_compile_definitions(MCL_DONOT_USE_ASM=1)

# ---- 1. 引入 mcl v1.66 源 ----
add_subdirectory(src/mcl)

# 开启 KSS-16，设置 768-bit p（8×64） / 256-bit r（4×64）
target_compile_definitions(mclbn384_256 PUBLIC
    MCLBN_CURVE_KSS16
    MCLBN_FP_UNIT_SIZE=8
    MCLBN_FR_UNIT_SIZE=4)

# ---- 2. pybind11 扩展 ----
find_package(pybind11 REQUIRED)

pybind11_add_module(kss16core src/bindings.cpp)
target_link_libraries(kss16core PRIVATE mclbn384_256)

set_target_properties(kss16core PROPERTIES OSX_ARCHITECTURES "arm64")
target_compile_features(kss16core PRIVATE cxx_std_17)
# Minimum required version of CMake  
# Define the project name and supported languages  
# Disable MCL's assembly optimizations globally  
# Add MCL source directory to the build  
# Set up KSS16 curve and parameter sizes  
# Use the KSS16 pairing-friendly curve  
# Field size: 768 bits (8 x 64-bit words)  
# Scalar field size: 256 bits (4 x 64-bit words)  
# Locate pybind11 package  
# Create a Python extension module from bindings.cpp  
# Link the module with MCL  
# Set build architecture to ARM64 for macOS  
# Use C++17 standard  
