#include <iostream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <algorithm>
#include <set>

using json = nlohmann::json;
namespace fs = std::filesystem;

std::mutex output_mutex;
std::mutex results_mutex;

struct Rule {
    std::string name, extension, pattern, severity, confidence;
    std::string cve, recommendation, category, owasp, mitre;
};

struct Vulnerability {
    std::string rule_name;
    std::string category;
    fs::path file_path;
    int line;
    std::string severity;
    std::string confidence;
    std::string owasp;
    std::string mitre;
    std::string cve;
    std::string recommendation;
    bool operator<(const Vulnerability& other) const {
        if (file_path != other.file_path) return file_path < other.file_path;
        if (line != other.line) return line < other.line;
        if (rule_name != other.rule_name) return rule_name < other.rule_name;
        if (category != other.category) return category < other.category;
        return false;
    }
    bool operator==(const Vulnerability& other) const {
        return file_path == other.file_path &&
               line == other.line &&
               rule_name == other.rule_name &&
               category == other.category &&
               severity == other.severity &&
               confidence == other.confidence &&
               owasp == other.owasp &&
               mitre == other.mitre &&
               cve == other.cve &&
               recommendation == other.recommendation;
    }
};

struct Config {
    int thread_count = 5;
    std::string rules_file = "rules.json";
};

std::vector<Vulnerability> all_vulnerabilities;

void show_help(const std::string& program_name) {
    unsigned int max_threads = std::thread::hardware_concurrency();
    if (max_threads == 0) max_threads = 5;

    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  -h, --help          Show this help message and exit\n"
              << "  -t, --threads NUM   Number of threads to use for scanning\n"
              << "                      (default: 5, max: " << max_threads << ")\n"
              << "  -r, --rules FILE    JSON file containing scanning rules\n"
              << "                      (default: rules.json)\n"
              << "\nExample:\n"
              << "  " << program_name << " -t 8 -r custom_rules.json\n"
              << "  " << program_name << " --threads 3 --rules myrules.json\n";
}

Config parse_arguments(int argc, char* argv[]) {
    Config config;
    unsigned int max_threads = std::thread::hardware_concurrency();
    if (max_threads == 0) max_threads = 5;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            show_help(argv[0]);
            exit(0);
        }
        else if (arg == "-t" || arg == "--threads") {
            if (i + 1 < argc) {
                try {
                    int threads = std::stoi(argv[++i]);
                    if (threads < 1) {
                        std::cerr << "Error: Thread count must be at least 1\n";
                        exit(1);
                    }
                    if (threads > static_cast<int>(max_threads)) {
                        std::cerr << "Warning: Requested " << threads
                                  << " threads, but system recommends maximum "
                                  << max_threads << ". Using " << max_threads << ".\n";
                        config.thread_count = max_threads;
                    } else {
                        config.thread_count = threads;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid thread count: " << argv[i] << "\n";
                    exit(1);
                }
            } else {
                std::cerr << "Error: --threads requires a value\n";
                exit(1);
            }
        }
        else if (arg == "-r" || arg == "--rules") {
            if (i + 1 < argc) {
                config.rules_file = argv[++i];
            } else {
                std::cerr << "Error: --rules requires a filename\n";
                exit(1);
            }
        }
        else {
            std::cerr << "Unknown option: " << arg << "\n";
            show_help(argv[0]);
            exit(1);
        }
    }

    return config;
}

bool matchesExtension(const fs::path& filePath, const std::string& ruleExtension) {
    if (ruleExtension == "*") return true;
    if (ruleExtension == ".*") return true;

    std::string fileExt = filePath.extension().string();
    if (ruleExtension.find("*.") == 0) {
        std::string expectedExt = ruleExtension.substr(1);
        return fileExt == expectedExt;
    }

    if (ruleExtension[0] == '.') {
        if (ruleExtension == ".yaml" || ruleExtension == ".yml") {
            return fileExt == ".yaml" || fileExt == ".yml";
        }
        return fileExt == ruleExtension;
    }

    if (ruleExtension.find('.') == std::string::npos) {
        return filePath.filename() == ruleExtension;
    }

    return filePath.filename() == ruleExtension;
}

void addVulnerability(const Rule& rule, const fs::path& filePath, int lineNum) {
    Vulnerability vuln{
        rule.name,
        rule.category,
        filePath,
        lineNum,
        rule.severity,
        rule.confidence,
        rule.owasp,
        rule.mitre,
        rule.cve,
        rule.recommendation
    };
    std::lock_guard<std::mutex> lock(results_mutex);
    all_vulnerabilities.push_back(vuln);
}

void printVulnerabilities() {
    if (all_vulnerabilities.empty()) {
        std::cout << "No vulnerabilities found.\n";
        return;
    }
    std::sort(all_vulnerabilities.begin(), all_vulnerabilities.end());
    auto last = std::unique(all_vulnerabilities.begin(), all_vulnerabilities.end());
    all_vulnerabilities.erase(last, all_vulnerabilities.end());
    std::cout << "\n=============================================\n";
    std::cout << "FOUND " << all_vulnerabilities.size() << " UNIQUE VULNERABILITIES\n";
    std::cout << "=============================================\n\n";
    std::map<std::string, int> severity_count;
    std::map<std::string, int> category_count;
    for (const auto& vuln : all_vulnerabilities) {
        severity_count[vuln.severity]++;
        category_count[vuln.category]++;
        std::cout << "---------------------------------------------\n";
        std::cout << "VULNERABILITY: " << vuln.rule_name << "\n";
        std::cout << "CATEGORY: " << vuln.category << "\n";
        std::cout << "FILE: " << vuln.file_path.string() << "\n";
        std::cout << "LINE: " << vuln.line << "\n";
        std::cout << "SEVERITY: " << vuln.severity << "\n";
        std::cout << "CONFIDENCE: " << vuln.confidence << "\n";
        std::cout << "OWASP: " << vuln.owasp << "\n";
        std::cout << "MITRE: " << vuln.mitre << "\n";
        std::cout << "CVE: " << vuln.cve << "\n";
        std::cout << "RECOMMENDATION: " << vuln.recommendation << "\n";
        std::cout << "---------------------------------------------\n\n";
    }
    std::cout << "\n=============================================\n";
    std::cout << "SUMMARY\n";
    std::cout << "=============================================\n";
    std::cout << "Total unique vulnerabilities: " << all_vulnerabilities.size() << "\n\n";
    std::cout << "By severity:\n";
    for (const auto& [severity, count] : severity_count) {
        std::cout << "  " << severity << ": " << count << "\n";
    }
    std::cout << "\nBy category:\n";
    for (const auto& [category, count] : category_count) {
        std::cout << "  " << category << ": " << count << "\n";
    }
}

void scanFile(const Rule& rule, const fs::path& filePath) {
    std::regex re;
    try {
        re = std::regex(rule.pattern);
    } catch (const std::regex_error& e) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cerr << "Regex error in rule '" << rule.name << "': " << e.what() << std::endl;
        return;
    }

    std::ifstream f(filePath);
    if (!f) return;

    std::string line;
    int ln = 0;
    while (std::getline(f, line)) {
        ln++;
        try {
            if (std::regex_search(line, re)) {
                addVulnerability(rule, filePath, ln);
            }
        } catch (const std::regex_error& e) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cerr << "Regex search error in file " << filePath
                      << " line " << ln << ": " << e.what() << std::endl;
        }
    }
}

void scanRule(const Rule& rule, int thread_id, int total_threads) {
    std::vector<fs::path> files;
    for (const auto& entry : fs::recursive_directory_iterator(".")) {
        if (!entry.is_regular_file()) continue;

        if (matchesExtension(entry.path(), rule.extension)) {
            files.push_back(entry.path());
        }
    }

    for (size_t i = thread_id; i < files.size(); i += total_threads) {
        scanFile(rule, files[i]);
    }
}

int main(int argc, char* argv[]) {
    Config config = parse_arguments(argc, argv);

    std::cout << "Starting scan with:\n"
              << "  Threads: " << config.thread_count << "\n"
              << "  Rules file: " << config.rules_file << "\n"
              << "---------------------------------------------\n";

    std::ifstream rf(config.rules_file);
    if (!rf) {
        std::cerr << "Error: Cannot open rules file '" << config.rules_file << "'\n";
        return 1;
    }

    json j;
    try {
        rf >> j;
    } catch (const json::parse_error& e) {
        std::cerr << "JSON parse error in '" << config.rules_file << "': " << e.what() << std::endl;
        return 1;
    }

    std::vector<Rule> rules;
    for (auto& r : j["rules"]) {
        try {
            Rule rule{
                r["name"].get<std::string>(),
                r["extension"].get<std::string>(),
                r["regex"].get<std::string>(),
                r["severity"].get<std::string>(),
                r["confidence"].get<std::string>(),
                r["cve"].get<std::string>(),
                r["recommendation"].get<std::string>(),
                r["category"].get<std::string>(),
                r["owasp"].get<std::string>(),
                r["mitre"].get<std::string>()
            };
            rules.push_back(rule);
        } catch (const json::exception& e) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cerr << "Error parsing rule: " << e.what() << std::endl;
        }
    }

    std::cout << "Loaded " << rules.size() << " scanning rules\n";
    std::cout << "Scanning...\n";

    for (const auto& rule : rules) {
        std::vector<std::thread> threads;

        for (int i = 0; i < config.thread_count; ++i) {
            threads.emplace_back(scanRule, std::cref(rule), i, config.thread_count);
        }

        for (auto& t : threads) {
            t.join();
        }
    }

    printVulnerabilities();

    return 0;
}
