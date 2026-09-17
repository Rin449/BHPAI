cmake_minimum_required(VERSION 3.16)
project(BHPAI_OpenSource C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Include Directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Core/Decompile
    ${CMAKE_CURRENT_SOURCE_DIR}/Core/scanner
    ${CMAKE_CURRENT_SOURCE_DIR}/Core/pack
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzy
    ${CMAKE_CURRENT_SOURCE_DIR}/Analyzers/Common
    ${CMAKE_CURRENT_SOURCE_DIR}/Core/license
)

# Compiler flags
add_compile_options(
    -Wall
    -Wextra
    -O2
    -ffunction-sections
    -fdata-sections
)

# Specific flag for AVX2 accelerated StringEx.cpp
set_source_files_properties(Core/scanner/StringEx.cpp PROPERTIES COMPILE_FLAGS "-mavx2")

# ------------------------------------------------------------------------------
# Core Objects Library
# ------------------------------------------------------------------------------
add_library(bhpai_core OBJECT
    Core/scanner/pe_features.cpp
    Core/scanner/pe_opcode_ngram.cpp
    Core/scanner/pe_api_ngram.cpp
    Core/scanner/StringEx.cpp
    Core/scanner/YaraGen.cpp
    Core/scanner/hash_utils.cpp
    Core/scanner/detect.cpp
    Core/Decompile/Disassembler.cpp
    Core/Decompile/PeParser.cpp
    Core/scanner/opcode_tfidf.cpp
    Core/pack/WWPack.cpp
    Core/pack/UPX.cpp
    Core/scanner/CFG.cpp
    Core/scanner/BehavioralGraph.cpp
    Core/scanner/cbpra.cpp
    fuzzy/fuzzyhash.c
    Analyzers/Common/FileRouter.cpp
    Analyzers/Common/AnalysisNode.cpp
    Analyzers/Common/AnalysisBudget.cpp
    Analyzers/Common/MitreMapper.cpp
    Analyzers/Common/IOC/IOCExtractor.cpp
)

# ------------------------------------------------------------------------------
# Target: pe_analyzer.exe
# ------------------------------------------------------------------------------
add_executable(pe_analyzer
    Core/scanner/pe_analyzer.cpp
    $<TARGET_OBJECTS:bhpai_core>
)

target_link_libraries(pe_analyzer PRIVATE
    capstone ssl crypto wintrust version ws2_32 psapi crypt32
    -static-libgcc -static-libstdc++
)
