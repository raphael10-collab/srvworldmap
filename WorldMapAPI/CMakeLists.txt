cmake_minimum_required(VERSION 3.15...4.2)

project(WorldMapAPI)


include(CMakePrintHelpers)

include(FetchContent)

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_STANDARD 23)
#set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


set(WEBKIT_DISABLE_COMPOSITING_MODE=1)


#if defined(__linux__)
    set(sep "\\")
#else
    set(sep "\/")


set(CD "${CMAKE_CURRENT_SOURCE_DIR}")
set(BUILDDIR "builddir")
set(SRC "src")

find_package(Threads)

find_package(PkgConfig REQUIRED)



# https://github.com/julp/FindICU.cmake
find_package(ICU 74.0 COMPONENTS uc i18n REQUIRED)
include_directories(${ICU_INCLUDE_DIRS})

# https://cmake.org/cmake/help/latest/variable/CMAKE_SYSTEM_NAME.html#system-names-known-to-cmake


add_executable(${PROJECT_NAME}
    src/main.cpp
    src/controllers/TileController.cpp
    src/controllers/AuthController.cpp
    src/controllers/MarkerController.cpp
    src/filters/AuthFilter.cpp
    src/services/TileService.cpp
    src/services/MapCommandService.cpp
    src/services/SessionService.cpp
    src/plugins/NatsPlugin.cpp
)


# https://github.com/PBfordev/wxecharts/blob/main/CMakeLists.txt

#add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/thirdparty/SQLiteCpp)


target_link_directories(${PROJECT_NAME} PUBLIC
    ./src/sodium
    ./src/nats/server
    ./src/nats/nats-client/lib
)

target_link_directories(${PROJECT_NAME} PUBLIC
    ./src/jsoncpp/lib
)

target_link_directories(${PROJECT_NAME} PUBLIC
    ./src/drogon/lib
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ./src/nats/nats-client/include
    ./src/jsoncpp/include
    ./src/drogon/include
)

target_link_libraries (${PROJECT_NAME} PRIVATE
    sodium
    nats
    jsoncpp
    nlohmann_json PRIVATE nlohmann_json::nlohmann_json
    trantor
    drogon
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    crypt
    crypto
)

cmake_print_variables(CMAKE_BINARY_DIR)
cmake_print_variables(CMAKE_SOURCE_DIR)
