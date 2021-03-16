file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS *.cpp *.hpp)

add_executable(${PROJECT_NAME} ${SOURCES})


set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_include_directories(${PROJECT_NAME} PRIVATE ../linux-pe/includes)
target_link_libraries(${PROJECT_NAME} PRIVATE VTIL Threads::Threads)