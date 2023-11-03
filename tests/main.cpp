#include <catch.hpp>
#include <esp_log.h>
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

    unsigned _vprintf_indent_amount = 0;

    extern "C" int vprintf_indent(const char *fmt, va_list argp) {
        std::string fmt_s(std::min(_vprintf_indent_amount, 50u) * 2, '.');
        fmt_s += fmt;
        return std::vprintf(fmt_s.c_str(), argp);
    }

    class SpookyReporter : public Catch::StreamingReporterBase {
        struct section {
            std::string full_name;
            Catch::Counts counts;
        };
        std::vector<section> _stack;
        std::map<std::string, Catch::Counts> _all_sections;

        vprintf_like_t _orig_vprintf = nullptr;

        void push_section(std::string name) {
            if (not _stack.empty()) {
                name = mlab::concatenate({_stack.back().full_name, "/", name});
            }
            _stack.emplace_back(section{std::move(name), {}});
            _vprintf_indent_amount += 1;
        }

        [[nodiscard]] section pop_section(Catch::Counts counts) {
            // Save the counts for this section
            _stack.back().counts += counts;
            // As this section ends, make sure you have saved (by name) the outcome
            if (auto it = _all_sections.try_emplace(_stack.back().full_name).first; it != std::end(_all_sections)) {
                it->second += counts;
            }
            // Also add the total assertions into the parent.
            section retval = std::move(_stack.back());
            _stack.pop_back();
            _stack.back().counts += counts;
            _vprintf_indent_amount -= 1;
            return retval;
        }

        [[nodiscard]] static std::string get_indent_str(char c = '>', int delta = 0) {
            std::string indent(std::max(0, int(_vprintf_indent_amount) + delta) * 2, '>');
            if (not indent.empty()) {
                indent += " ";
            }
            return indent;
        }

        static void print_starting_header(std::string const &name, const char *slug) {
            const auto indent = get_indent_str('>', -1);
            std::printf("%s%s%s %s%s %s\n", indent.c_str(), ansi_cyn, slug, "START", ansi_rst, name.c_str());
        }

        [[nodiscard]] static std::pair<const char *, const char *> get_status_and_ansi_color(Catch::Counts const &counts) {
            if (counts.failed > 0) {
                return {"FAIL", ansi_red};
            } else if (counts.skipped > 0) {
                return {"SKIP", ansi_mag};
            }
            return {"PASS", ansi_grn};
        }

        static void print_ending_header(std::string const &name, const char *slug, Catch::Counts const &counts) {
            const auto indent = get_indent_str();
            auto [log_str, log_str_col] = get_status_and_ansi_color(counts);

            std::printf("%s%s%s%s  %s%s%s %s\n", indent.c_str(), ansi_cyn, slug, ansi_rst, log_str_col, log_str, ansi_rst, name.c_str());
            std::printf("%s      %s%s%s %s%llu/%llu%s\n", indent.c_str(), ansi_cyn, "WITH", ansi_rst, log_str_col,
                        counts.passed, counts.total(), ansi_rst);
        }

        [[nodiscard]] std::string const &current_section_name() const {
            static const std::string _no_s = "<no section>";
            return _stack.empty() ? _no_s : _stack.back().full_name;
        }
    public:
        using Catch::StreamingReporterBase::StreamingReporterBase;

        [[nodiscard]] static std::string getDescription() {
            return "Custom reporter for libSpookyAction";
        }

        void testRunStarting(const Catch::TestRunInfo &testRunInfo) override {
//            _orig_vprintf = esp_log_set_vprintf(&vprintf_indent);
            std::printf("\n");
            StreamingReporterBase::testRunStarting(testRunInfo);
        }

        void testRunEnded(const Catch::TestRunStats &testRunInfo) override {
//            esp_log_set_vprintf(_orig_vprintf);
            const std::string sep(60, '-');

            std::printf("%s\n\n", sep.c_str());
            std::printf("%sSUMMARY%s\n\n", ansi_cyn, ansi_rst);

            std::size_t i = 0;
            for (auto const &[name, counts] : _all_sections) {
                auto [log_str, log_str_col] = get_status_and_ansi_color(counts);
                std::printf("%5d. %s%s%s %s\n", ++i, log_str_col, log_str, ansi_rst, name.c_str());
            }

            std::printf("\n%s\n\n", sep.c_str());

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

        void sectionStarting(const Catch::SectionInfo &sectionInfo) override {
            StreamingReporterBase::sectionStarting(sectionInfo);
            push_section(sectionInfo.name);
            print_starting_header(sectionInfo.name, "SECT");
        }

        void sectionEnded(const Catch::SectionStats &sectionInfo) override {
            auto s = pop_section(sectionInfo.assertions);
            print_ending_header(sectionInfo.sectionInfo.name, "SECT", s.counts);
            StreamingReporterBase::sectionEnded(sectionInfo);
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
            const auto indent = get_indent_str();
            switch (result.getResultType()) {
                case Catch::ResultWas::Info:
                    if (result.hasMessage()) {
                        std::printf("%s%sINFO%s  %s\n", indent.c_str(), ansi_cyn, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::Warning:
                    if (result.hasMessage()) {
                        std::printf("%s%sWARN%s  %s\n", indent.c_str(), ansi_yel, ansi_rst, result.getMessage().data());
                    }
                    break;
                case Catch::ResultWas::ExplicitSkip:
                    if (result.hasMessage()) {
                        std::printf("%s%sSKIP%s  %s\n", indent.c_str(), ansi_mag, ansi_rst, result.getMessage().data());
                    } else if (result.hasExpression()) {
                        std::printf("%s%sSKIP%s  %s\n", indent.c_str(), ansi_mag, ansi_rst, result.getExpressionInMacro().data());
                    }
                    break;
                default:
                    std::printf("%s%sFAIL  %s:%d%s\n", indent.c_str(), ansi_red, result.getSourceInfo().file, result.getSourceInfo().line, ansi_rst);
                    if (result.hasExpression()) {
                        std::printf("%s%s      %s%s\n", indent.c_str(), ansi_yel, result.getExpressionInMacro().data(), ansi_rst);
                    }
                    if (result.hasMessage()) {
                        std::printf("%s%s      %s%s\n", indent.c_str(), ansi_yel, result.getMessage().data(), ansi_rst);
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
    session.configData().noThrow = true;
    session.configData().reporterSpecifications = {Catch::ReporterSpec{"spooky", {}, {}, {}}};
    return session.run();
}
