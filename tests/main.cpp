#include <catch.hpp>
#include <mlab/strutils.hpp>

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

    class SpookyReporter : public Catch::StreamingReporterBase {
        std::vector<std::string> _sect_names = {"root"};
        Catch::Counts _test_assertions{};

        [[nodiscard]] static std::pair<const char *, const char *> get_status_and_ansi_color(Catch::Counts const &counts) {
            if (counts.failed > 0) {
                return {"FAIL", ansi_red};
            } else if (counts.skipped > 0) {
                return {"SKIP", ansi_mag};
            }
            return {"PASS", ansi_grn};
        }

        [[nodiscard]] std::string_view active_section_name() const {
            if (_sect_names.empty()) {
                return "";
            }
            return _sect_names.back();
        }

        void push_name(std::string_view s) {
            if (_sect_names.empty()) {
                _sect_names.emplace_back(s);
            } else {
                _sect_names.push_back(mlab::concatenate({_sect_names.back(), "/", s}));
            }
        }

        void pop_name() {
            if (not _sect_names.empty()) {
                _sect_names.pop_back();
            }
        }

    public:
        using Catch::StreamingReporterBase::StreamingReporterBase;

        [[nodiscard]] static std::string getDescription() {
            return "Custom reporter for libSpookyAction";
        }

        void sectionStarting(const Catch::SectionInfo &sectionInfo) override {
            StreamingReporterBase::sectionStarting(sectionInfo);
            push_name(sectionInfo.name);
            std::printf("%sSECT START%s %s\n", ansi_blu, ansi_rst, active_section_name().data());
        }

        void sectionEnded(const Catch::SectionStats &sectionInfo) override {
            _test_assertions += sectionInfo.assertions;
            auto [log_str, log_str_col] = get_status_and_ansi_color(sectionInfo.assertions);
            std::printf("%sSECT%s %s%s%s %s\n", ansi_blu, ansi_rst, log_str_col, log_str, ansi_rst, active_section_name().data());
            std::printf("%sWITH%s %s%llu/%llu%s (%llu skip)\n", ansi_blu, ansi_rst, log_str_col,
                        sectionInfo.assertions.passed, sectionInfo.assertions.total(), ansi_rst, sectionInfo.assertions.skipped);
            pop_name();
            StreamingReporterBase::sectionEnded(sectionInfo);
        }

        void testCaseStarting(const Catch::TestCaseInfo &testInfo) override {
            StreamingReporterBase::testCaseStarting(testInfo);
            push_name(testInfo.name);
            _test_assertions = {};
            std::printf("%sTEST START%s %s\n", ansi_cyn, ansi_rst, active_section_name().data());
        }

        void testCaseEnded(const Catch::TestCaseStats &testStats) override {
            _test_assertions += testStats.totals.assertions;
            auto [log_str, log_str_col] = get_status_and_ansi_color(_test_assertions);
            std::printf("%sTEST%s %s%s%s %s\n", ansi_cyn, ansi_rst, log_str_col, log_str, ansi_rst, active_section_name().data());
            std::printf("%sWITH%s %s%llu/%llu%s (%llu skip)\n", ansi_cyn, ansi_rst, log_str_col,
                        _test_assertions.passed, _test_assertions.total(), ansi_rst, _test_assertions.skipped);
            pop_name();
            StreamingReporterBase::testCaseEnded(testStats);
        }

        void assertionEnded(const Catch::AssertionStats &stats) override {
            StreamingReporterBase::assertionEnded(stats);
            auto const &result = stats.assertionResult;
            if (result.isOk() and result.getResultType() != Catch::ResultWas::Warning and result.getResultType() != Catch::ResultWas::ExplicitSkip) {
                return;
            }
            switch (result.getResultType()) {
                case Catch::ResultWas::Info:
                    if (result.hasMessage()) {
                        std::printf("%sINFO%s %s\n", ansi_cyn, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::Warning:
                    if (result.hasMessage()) {
                        std::printf("%sWARN%s %s\n", ansi_yel, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::ExplicitSkip:
                    if (result.hasMessage()) {
                        std::printf("%sSKIP%s %s\n", ansi_mag, ansi_rst, result.getMessage().data());
                    } else if (result.hasExpression()) {
                        std::printf("%sSKIP%s %s\n", ansi_mag, ansi_rst, result.getExpressionInMacro().data());
                    }
                    break;
                default:
                    std::printf("%sFAIL %s:%d%s\n", ansi_red, result.getSourceInfo().file, result.getSourceInfo().line, ansi_rst);
                    if (result.hasExpression()) {
                        std::printf("%s     %s%s\n", ansi_yel, result.getExpressionInMacro().data(), ansi_rst);
                    }
                    if (result.hasMessage()) {
                        std::printf("%s     %s%s\n", ansi_yel, result.getMessage().data(), ansi_rst);
                    }
                    break;
            }
        }
    };
    CATCH_REGISTER_REPORTER("spooky", SpookyReporter)

}// namespace


extern "C" int app_main() {
    Catch::Session session;
    session.configData().name = "libSpookyAction";
    session.configData().runOrder = Catch::TestRunOrder::LexicographicallySorted;
    session.configData().verbosity = Catch::Verbosity::Quiet;
    session.configData().noThrow = true;
    session.configData().reporterSpecifications = {Catch::ReporterSpec{"spooky", {}, {}, {}}};
    return session.run();
}
