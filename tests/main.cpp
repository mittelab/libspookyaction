#include <catch.hpp>
#include <esp_log.h>

namespace {

    constexpr auto ansi_rst = "\33[0m";
    constexpr auto ansi_blk = "\33[0;30m";
    constexpr auto ansi_red = "\33[0;31m";
    constexpr auto ansi_grn = "\33[0;32m";
    constexpr auto ansi_yel = "\33[0;33m";
    constexpr auto ansi_blu = "\33[0;34m";
    constexpr auto ansi_mag = "\33[0;35m";
    constexpr auto ansi_cyn = "\33[0;36m";
    constexpr auto ansi_wht = "\33[0;37m";

    extern "C" int vprintf_indent(const char *fmt, va_list argp) {
        std::string fmt_s = fmt;
        fmt_s = "     " + fmt_s;
        return std::vprintf(fmt_s.c_str(), argp);
    }

    class SpookyReporter : public Catch::StreamingReporterBase {
    public:
        using Catch::StreamingReporterBase::StreamingReporterBase;

        [[nodiscard]] static std::string getDescription() {
            return "Custom reporter for libSpookyAction";
        }

        void testCaseStarting(const Catch::TestCaseInfo &testInfo) override {
            StreamingReporterBase::testCaseStarting(testInfo);
            std::printf("\n---- %sSTART%s %s\n", ansi_cyn, ansi_rst, testInfo.name.c_str());
        }

        void testCaseEnded(const Catch::TestCaseStats &stats) override {
            auto col = stats.totals.assertions.allPassed() ? ansi_grn : ansi_red;
            std::printf("%s---- %llu ASSERTIONS, %llu PASS, %llu FAIL, %llu SKIP%s\n",
                        col,
                        stats.totals.assertions.total(),
                        stats.totals.assertions.passed,
                        stats.totals.assertions.failed,
                        stats.totals.assertions.failedButOk,
                        ansi_rst);

            auto log_str = stats.totals.assertions.allPassed() ? "PASS " : "FAIL ";
            std::printf("---- %s%s%s %s\n\n", col, log_str, ansi_rst, stats.testInfo->name.c_str());
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
                        std::printf("%s     %s%s\n", ansi_wht, result.getMessage().data(), ansi_rst);
                    }
                    break;
                case Catch::ResultWas::Warning:
                    if (result.hasMessage()) {
                        std::printf("%s     %s%s\n", ansi_yel, result.getMessage().data(), ansi_rst);
                    }
                    break;
                case Catch::ResultWas::ExplicitSkip:
                    if (result.hasMessage()) {
                        std::printf("%s     SKIP %s%s\n", ansi_yel, result.getMessage().data(), ansi_rst);
                    } else if (result.hasExpression()) {
                        std::printf("%s     SKIP %s%s\n", ansi_yel, result.getExpressionInMacro().data(), ansi_rst);
                    }
                    break;
                default:
                    std::printf("%s     FAIL %s:%d%s\n", ansi_red, result.getSourceInfo().file, result.getSourceInfo().line, ansi_rst);
                    if (result.hasExpression()) {
                        std::printf("%s          %s%s\n", ansi_red, result.getExpressionInMacro().data(), ansi_rst);
                    }
                    if (result.hasMessage()) {
                        std::printf("%s          %s%s\n", ansi_red, result.getMessage().data(), ansi_rst);
                    }
                    break;
            }
        }
    };

    CATCH_REGISTER_REPORTER("spooky", SpookyReporter);
}// namespace

extern "C" int app_main() {
    Catch::Session session;
    session.configData().runOrder = Catch::TestRunOrder::LexicographicallySorted;
    session.configData().verbosity = Catch::Verbosity::Quiet;
    session.configData().reporterSpecifications = {Catch::ReporterSpec{"spooky", {}, {}, {}}};
    esp_log_set_vprintf(&vprintf_indent);
    return session.run();
}
