#include <catch.hpp>
#include <mlab/strutils.hpp>

extern "C" int app_main() {
    Catch::Session session;
    session.configData().runOrder = Catch::TestRunOrder::LexicographicallySorted;
    session.configData().verbosity = Catch::Verbosity::Quiet;
    session.configData().noThrow = true;
    return session.run();
}
