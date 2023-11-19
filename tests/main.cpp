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
        std::vector<std::string> _sect_names = {};
        Catch::Counts _test_assertions{};

        static std::atomic<unsigned> _indent;
        static vprintf_like_t _orig_printf;


        static auto generate_indent_str() {
            return std::string(std::min(_indent.load(), 50u) * 2, ' ');
        }

        static int vprintf_indent(const char *fmt, va_list argp) {
            std::string fmt_s = generate_indent_str();
            fmt_s += fmt;
            return std::vprintf(fmt_s.c_str(), argp);
        }


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

        void started(std::string_view name, std::string_view slug) {
            push_name(name);
            const auto fmt_s = generate_indent_str();
            std::printf("%s%s%s START%s %s\n", fmt_s.c_str(), ansi_cyn, slug.data(), ansi_rst, name.data());
            _indent++;
        }

        void ended(Catch::Counts const &counts, std::string_view slug) {
            auto [log_str, log_str_col] = get_status_and_ansi_color(counts);
            const auto fmt_s = generate_indent_str();
            std::printf("%s%sSECT%s  %s%s%s %s\n", fmt_s.c_str(), ansi_cyn, ansi_rst, log_str_col, log_str, ansi_rst, active_section_name().data());
            std::printf("%s%sSECT  WITH%s %s%llu/%llu%s (%llu skip)\n", fmt_s.c_str(), ansi_cyn, ansi_rst, log_str_col,
                        counts.passed, counts.total(), ansi_rst, counts.skipped);
            pop_name();
        }


    public:
        using Catch::StreamingReporterBase::StreamingReporterBase;

        [[nodiscard]] static std::string getDescription() {
            return "Custom reporter for libSpookyAction";
        }

        void testRunStarting(const Catch::TestRunInfo &_testRunInfo) override {
            _orig_printf = esp_log_set_vprintf(&vprintf_indent);
        }

        void testRunEnded(const Catch::TestRunStats &) override {
            esp_log_set_vprintf(_orig_printf);
        }

        void sectionStarting(const Catch::SectionInfo &sectionInfo) override {
            StreamingReporterBase::sectionStarting(sectionInfo);
            started(sectionInfo.name, "SECT");
        }

        void sectionEnded(const Catch::SectionStats &sectionInfo) override {
            _indent--;
            _test_assertions += sectionInfo.assertions;
            ended(sectionInfo.assertions, "SECT");
            StreamingReporterBase::sectionEnded(sectionInfo);
        }

        void testCaseStarting(const Catch::TestCaseInfo &testInfo) override {
            StreamingReporterBase::testCaseStarting(testInfo);
            started(testInfo.name, "CASE");
            _test_assertions = {};
        }

        void testCaseEnded(const Catch::TestCaseStats &testStats) override {
            _indent--;
            _test_assertions += testStats.totals.assertions;
            ended(_test_assertions, "CASE");
            StreamingReporterBase::testCaseEnded(testStats);
        }

        void assertionEnded(const Catch::AssertionStats &stats) override {
            StreamingReporterBase::assertionEnded(stats);
            auto const &result = stats.assertionResult;
            if (result.isOk() and result.getResultType() != Catch::ResultWas::Warning and result.getResultType() != Catch::ResultWas::ExplicitSkip) {
                return;
            }
            const auto fmt_s = generate_indent_str();
            switch (result.getResultType()) {
                case Catch::ResultWas::Info:
                    if (result.hasMessage()) {
                        std::printf("%s%sINFO%s %s\n", fmt_s.c_str(), ansi_cyn, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::Warning:
                    if (result.hasMessage()) {
                        std::printf("%s%sWARN%s %s\n", fmt_s.c_str(), ansi_yel, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::ExplicitSkip:
                    if (result.hasMessage()) {
                        std::printf("%s%sSKIP%s %s\n", fmt_s.c_str(), ansi_mag, ansi_rst, result.getMessage().data());
                    } else if (result.hasExpression()) {
                        std::printf("%s%sSKIP%s %s\n", fmt_s.c_str(), ansi_mag, ansi_rst, result.getExpressionInMacro().data());
                    }
                    break;
                default:
                    std::printf("%s%sFAIL %s:%d%s ", fmt_s.c_str(), ansi_red, result.getSourceInfo().file, result.getSourceInfo().line, ansi_rst);
                    if (result.hasExpression()) {
                        std::printf("%s%s%s\n", ansi_yel, result.getExpressionInMacro().data(), ansi_rst);
                    }
                    if (result.hasMessage()) {
                        std::printf("%s%s%s\n", ansi_yel, result.getMessage().data(), ansi_rst);
                    }
                    break;
            }
        }
    };
    CATCH_REGISTER_REPORTER("spooky", SpookyReporter)

    std::atomic<unsigned> SpookyReporter::_indent{0};
    vprintf_like_t SpookyReporter::_orig_printf{nullptr};

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
