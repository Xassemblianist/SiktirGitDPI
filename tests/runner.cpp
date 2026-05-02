// Single TU that pulls in test_main.hpp and emits the entry point. The
// individual test_*.cpp files register themselves into the global registry
// via static initializers when linked together.

#include "test_main.hpp"

int main() { return ::sgdpi_tests::run(); }
