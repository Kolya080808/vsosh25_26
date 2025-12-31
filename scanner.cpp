
#include <iostream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;

std::mutex print_mutex;

struct Rule {
    std::string name, extension, pattern, severity, confidence;
    std::string cve, recommendation, category, owasp, mitre;
};

void scan(const Rule& rule) {
    std::regex re(rule.pattern, std::regex::icase);
    for (const auto& file : fs::recursive_directory_iterator(".")) {
        if (!file.is_regular_file()) continue;
        if (file.path().extension() != rule.extension) continue;

        std::ifstream f(file.path());
        if (!f) continue;

        std::string line;
        int ln = 0;
        while (std::getline(f, line)) {
            ln++;
            if (std::regex_search(line, re)) {
                std::lock_guard<std::mutex> lock(print_mutex);
                std::cout << "---------------------------------------------\n";
                std::cout << "VULNERABILITY: " << rule.name << "\n";
                std::cout << "CATEGORY: " << rule.category << "\n";
                std::cout << "FILE: " << file.path() << "\n";
                std::cout << "LINE: " << ln << "\n";
                std::cout << "SEVERITY: " << rule.severity << "\n";
                std::cout << "CONFIDENCE: " << rule.confidence << "\n";
                std::cout << "OWASP: " << rule.owasp << "\n";
                std::cout << "MITRE: " << rule.mitre << "\n";
                std::cout << "CVE: " << rule.cve << "\n";
                std::cout << "RECOMMENDATION: " << rule.recommendation << "\n";
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

    json j; rf >> j;
    std::vector<std::thread> threads;

    for (auto& r : j["rules"]) {
        Rule rule{
            r["name"], r["extension"], r["regex"],
            r["severity"], r["confidence"],
            r["cve"], r["recommendation"],
            r["category"], r["owasp"], r["mitre"]
        };
        threads.emplace_back(scan, rule);
    }

    for (auto& t : threads) t.join();
    return 0;
}
