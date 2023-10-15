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
        std::vector<std::pair<std::string, Catch::ResultWas::OfType>> _tests;
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
            esp_log_set_vprintf(_orig_vprintf);

            std::printf("%s\n\n", _sep.c_str());
            std::printf("%sSUMMARY%s\n\n", ansi_cyn, ansi_rst);

            for (std::size_t i = 0; i < _tests.size(); ++i) {
                auto const &[name, result_was] = _tests[i];
                switch (result_was) {
                    case Catch::ResultWas::Ok:
                        std::printf("%5d. %s%s%s %s\n", i + 1, ansi_grn, "PASS", ansi_rst, name.c_str());
                        break;
                    case Catch::ResultWas::ExplicitSkip:
                        std::printf("%5d. %s%s%s %s\n", i + 1, ansi_mag, "SKIP", ansi_rst, name.c_str());
                        break;
                    case Catch::ResultWas::ExplicitFailure:
                        std::printf("%5d. %s%s%s %s\n", i + 1, ansi_red, "FAIL", ansi_rst, name.c_str());
                        break;
                    default:
                        ESP_LOGE("CATCH", "Invalid result type.");
                        break;
                }
            }
            std::printf("\n%s\n\n", _sep.c_str());

            auto test_pass_color = testRunInfo.totals.testCases.failed == 0 ? ansi_grn : ansi_rst;
            auto test_fail_color = testRunInfo.totals.testCases.failed == 0 ? ansi_rst : ansi_red;
            auto test_skip_color = testRunInfo.totals.testCases.skipped == 0 ? ansi_rst : ansi_mag;

            auto assertion_pass_color = testRunInfo.totals.assertions.failed == 0 ? ansi_grn : ansi_rst;
            auto assertion_fail_color = testRunInfo.totals.assertions.failed == 0 ? ansi_rst : ansi_red;
            auto assertion_skip_color = testRunInfo.totals.assertions.skipped == 0 ? ansi_rst : ansi_mag;

            std::printf("%sTOT %s%s %4llu, %s%4llu PASS%s, %s%4llu FAIL%s, %s%4llu SKIP%s\n",
                        ansi_cyn, "     TESTS", ansi_rst,
                        testRunInfo.totals.testCases.total(),
                        test_pass_color, testRunInfo.totals.testCases.passed, ansi_rst,
                        test_fail_color, testRunInfo.totals.testCases.failed, ansi_rst,
                        test_skip_color, testRunInfo.totals.testCases.skipped, ansi_rst);

            std::printf("%sTOT %s%s %4llu, %s%4llu PASS%s, %s%4llu FAIL%s, %s%4llu SKIP%s\n",
                        ansi_cyn, "ASSERTIONS", ansi_rst,
                        testRunInfo.totals.assertions.total(),
                        assertion_pass_color, testRunInfo.totals.assertions.passed, ansi_rst,
                        assertion_fail_color, testRunInfo.totals.assertions.failed, ansi_rst,
                        assertion_skip_color, testRunInfo.totals.assertions.skipped, ansi_rst);

            auto percent_color = ansi_grn;
            if (testRunInfo.totals.testCases.skipped > 0) {
                percent_color = ansi_yel;
            }
            if (testRunInfo.totals.testCases.failed > 0) {
                percent_color = ansi_red;
            }
            auto tot_non_skipped_assertions = testRunInfo.totals.assertions.total() - testRunInfo.totals.assertions.skipped;
            auto percent = tot_non_skipped_assertions > 0
                    ? 100.f * float(testRunInfo.totals.assertions.passed) / float(tot_non_skipped_assertions)
                    : 100.f;

            std::printf("%sTOT %s%s %s%6.2f%%%s\n\n", ansi_cyn, "   PERCENT", ansi_rst, percent_color, percent, ansi_rst);

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
                _tests.emplace_back(stats.testInfo->name, Catch::ResultWas::OfType::ExplicitFailure);
            } else if (stats.totals.testCases.skipped > 0) {
                log_str = "SKIP";
                log_str_col = ansi_mag;
                _tests.emplace_back(stats.testInfo->name, Catch::ResultWas::OfType::ExplicitSkip);
            } else {
                _tests.emplace_back(stats.testInfo->name, Catch::ResultWas::OfType::Ok);
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
