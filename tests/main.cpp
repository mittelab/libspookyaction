#include <catch.hpp>
#include <esp_log.h>

namespace {

    constexpr auto ansi_rst [[maybe_unused]] = "\33[0m";
    constexpr auto ansi_blk [[maybe_unused]] = "\33[0;30m";
    constexpr auto ansi_red [[maybe_unused]] = "\33[0;31m";
    constexpr auto ansi_grn [[maybe_unused]] = "\33[0;32m";
    constexpr auto ansi_yel [[maybe_unused]] = "\33[0;33m";
    constexpr auto ansi_blu [[maybe_unused]] = "\33[0;34m";
    constexpr auto ansi_mag [[maybe_unused]] = "\33[0;35m";
    constexpr auto ansi_cyn [[maybe_unused]] = "\33[0;36m";
    constexpr auto ansi_wht [[maybe_unused]] = "\33[0;37m";

    extern "C" int vprintf_indent(const char *fmt, va_list argp) {
        std::string fmt_s = fmt;
        fmt_s = ".... " + fmt_s;
        return std::vprintf(fmt_s.c_str(), argp);
    }

    class SpookyReporter : public Catch::StreamingReporterBase {
        vprintf_like_t _orig_vprintf = nullptr;
        std::string _sep = std::string(60llu, '-');
        std::vector<std::string> _failed_tests;
    public:
        using Catch::StreamingReporterBase::StreamingReporterBase;

        [[nodiscard]] static std::string getDescription() {
            return "Custom reporter for libSpookyAction";
        }

        void testRunStarting(const Catch::TestRunInfo &testRunInfo) override {
            _orig_vprintf = esp_log_set_vprintf(&vprintf_indent);
            std::printf("%s\n\n", _sep.c_str());
            StreamingReporterBase::testRunStarting(testRunInfo);
        }

        void testRunEnded(const Catch::TestRunStats &testRunInfo) override {
            for (auto const &failedTest : _failed_tests) {
                std::printf("%sTEST%s %sFAIL%s %s\n", ansi_cyn, ansi_rst, ansi_red, ansi_rst, failedTest.c_str());
            }
            esp_log_set_vprintf(_orig_vprintf);
            StreamingReporterBase::testRunEnded(testRunInfo);
        }

        void testCaseStarting(const Catch::TestCaseInfo &testInfo) override {
            StreamingReporterBase::testCaseStarting(testInfo);
            std::printf("%sTEST START%s %s\n", ansi_cyn, ansi_rst, testInfo.name.c_str());
        }

        void testCaseEnded(const Catch::TestCaseStats &stats) override {
            const char *log_str = "PASS";
            const char *log_str_col = ansi_grn;

            if (stats.totals.testCases.failed > 0) {
                log_str = "FAIL";
                log_str_col = ansi_red;
                _failed_tests.emplace_back(stats.testInfo->name);
            } else if (stats.totals.testCases.skipped > 0) {
                log_str = "SKIP";
                log_str_col = ansi_mag;
            }

            std::printf("%sTEST%s %s%s%s  %s\n",
                        ansi_cyn, ansi_rst,
                        log_str_col, log_str, ansi_rst, stats.testInfo->name.c_str());

            if (stats.totals.testCases.skipped == 0) {
                std::printf("%sWITH%s       %llu/%llu assertions\n",
                            ansi_cyn, ansi_rst,
                            stats.totals.assertions.passed,
                            stats.totals.assertions.total());
            }

            std::printf("\n%s\n\n", _sep.c_str());
            StreamingReporterBase::testCaseEnded(stats);
        }

        void assertionEnded(const Catch::AssertionStats &stats) override {
            StreamingReporterBase::assertionEnded(stats);
            auto const &result = stats.assertionResult;
            if (result.isOk()
                and result.getResultType() != Catch::ResultWas::Warning
                and result.getResultType() != Catch::ResultWas::ExplicitSkip)
            {
                return;
            }
            switch (result.getResultType()) {
                case Catch::ResultWas::Info:
                    if (result.hasMessage()) {
                        std::printf(">>>> %sINFO%s  %s\n", ansi_cyn, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::Warning:
                    if (result.hasMessage()) {
                        std::printf(">>>> %sWARN%s  %s\n", ansi_yel, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::ExplicitSkip:
                    if (result.hasMessage()) {
                        std::printf(">>>> %sSKIP%s  %s\n", ansi_mag, ansi_rst, result.getMessage().data());
                    } else if (result.hasExpression()) {
                        std::printf(">>>> %sSKIP%s  %s\n", ansi_mag, ansi_rst, result.getExpressionInMacro().data());
                    }
                    break;
                default:
                    std::printf(">>>> %sFAIL  %s:%d%s\n", ansi_red, result.getSourceInfo().file, result.getSourceInfo().line, ansi_rst);
                    if (result.hasExpression()) {
                        std::printf(">>>> %s      %s%s\n", ansi_yel, result.getExpressionInMacro().data(), ansi_rst);
                    }
                    if (result.hasMessage()) {
                        std::printf(">>>> %s      %s%s\n", ansi_yel, result.getMessage().data(), ansi_rst);
                    }
                    break;
            }
        }
    };

    CATCH_REGISTER_REPORTER("spooky", SpookyReporter)
}// namespace

extern "C" int app_main() {
    Catch::Session session;
    session.configData().runOrder = Catch::TestRunOrder::LexicographicallySorted;
    session.configData().verbosity = Catch::Verbosity::Quiet;
    session.configData().reporterSpecifications = {Catch::ReporterSpec{"spooky", {}, {}, {}}};
    return session.run();
}
