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

using json = nlohmann::json;
namespace fs = std::filesystem;

std::mutex output_mutex;

struct Rule {
    std::string name, extension, pattern, severity, confidence;
    std::string cve, recommendation, category, owasp, mitre;
};

bool matchesExtension(const fs::path& filePath, const std::string& ruleExtension) {
    if (ruleExtension == "*") return true;

    if (ruleExtension.find("*.") == 0) {
        std::string expectedExt = ruleExtension.substr(1);
        return filePath.extension() == expectedExt;
    }

    if (ruleExtension[0] == '.') {
        return filePath.extension() == ruleExtension;
    }

    return filePath.filename() == ruleExtension;
}

std::string generateTempFilename() {
    static std::atomic<int> counter{0};
    std::stringstream ss;
    ss << "vuln_" << std::this_thread::get_id() << "_" << counter.fetch_add(1) << ".tmp";
    return ss.str();
}

void writeAndPrintVulnerability(const Rule& rule, const fs::path& filePath, int lineNum) {
    std::string tempFile = generateTempFilename();

    {
        std::ofstream outFile(tempFile);
        if (!outFile) return;

        outFile << "---------------------------------------------\n";
        outFile << "VULNERABILITY: " << rule.name << "\n";
        outFile << "CATEGORY: " << rule.category << "\n";
        outFile << "FILE: " << filePath.string() << "\n";
        outFile << "LINE: " << lineNum << "\n";
        outFile << "SEVERITY: " << rule.severity << "\n";
        outFile << "CONFIDENCE: " << rule.confidence << "\n";
        outFile << "OWASP: " << rule.owasp << "\n";
        outFile << "MITRE: " << rule.mitre << "\n";
        outFile << "CVE: " << rule.cve << "\n";
        outFile << "RECOMMENDATION: " << rule.recommendation << "\n";
    }

    {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::ifstream inFile(tempFile);
        if (inFile) {
            std::cout << inFile.rdbuf();
        }
    }

    fs::remove(tempFile);
}

void scan(const Rule& rule) {
    std::regex re;
    try {
        re = std::regex(rule.pattern);
    } catch (const std::regex_error& e) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cerr << "Regex error in rule '" << rule.name << "': " << e.what() << std::endl;
        return;
    }

    for (const auto& entry : fs::recursive_directory_iterator(".")) {
        if (!entry.is_regular_file()) continue;

        if (!matchesExtension(entry.path(), rule.extension)) {
            continue;
        }

        std::ifstream f(entry.path());
        if (!f) continue;

        std::string line;
        int ln = 0;
        while (std::getline(f, line)) {
            ln++;
            try {
                if (std::regex_search(line, re)) {
                    writeAndPrintVulnerability(rule, entry.path(), ln);
                }
            } catch (const std::regex_error& e) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cerr << "Regex search error in file " << entry.path() 
                          << " line " << ln << ": " << e.what() << std::endl;
            }
        }
    }
}

int main() {
    std::ifstream rf("rules.json");
    if (!rf) {
        std::cerr << "rules.json not found\n";
        return 1;
    }

    json j;
    try {
        rf >> j;
    } catch (const json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
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

    std::vector<std::thread> threads;
    for (auto& rule : rules) {
        threads.emplace_back(scan, rule);
    }

    for (auto& t : threads) {
        t.join();
    }
    return 0;
}
