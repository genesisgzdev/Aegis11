#include "CLI/ArgumentParser.hpp"
#include <stdexcept>
#include <iostream>
int main() {
    try {
        char program[] = "aegis11";
        char preview[] = "--preview";
        char legacy[] = "--simulate";
        char snapshot[] = "--snapshot";
        char* current[] = {program, preview};
        char* old[] = {program, legacy};
        char* conflict[] = {program, preview, snapshot, program};
        if (!Aegis::CLI::ArgumentParser::Parse(2, current).simulate ||
            !Aegis::CLI::ArgumentParser::Parse(2, old).simulate ||
            !Aegis::CLI::ArgumentParser::Parse(4, conflict).invalid) {
            throw std::runtime_error("preview alias or exclusive-mode validation failed");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
