#include <catch.hpp>

extern "C" int app_main() {
    Catch::Session session;
    session.configData().name = "libSpookyAction";
    session.configData().runOrder = Catch::TestRunOrder::LexicographicallySorted;
    session.configData().verbosity = Catch::Verbosity::Quiet;
    session.configData().noThrow = true;
    const auto result = session.run();
    std::printf("GREPME done\n");
    return result;
}
