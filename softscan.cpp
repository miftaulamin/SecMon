#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
using namespace std;

int main() {

#ifdef _WIN32
    // ------------------- WINDOWS -------------------
    system("reg query HKLM\\SOFTWARE > soft_raw.txt");

    ifstream in("soft_raw.txt");
    ofstream out("soft_clean.txt");
    string line;

    while (getline(in, line)) {
        if (line.find("SOFTWARE\\") != string::npos) {
            out << line << endl;
        }
    }

    cout << "Windows software scan complete" << endl;

#else
    // ------------------- LINUX -------------------
    // Try dpkg (Debian / Ubuntu)
    if (system("dpkg -l | awk 'NR>5 {print $2}' > soft_clean.txt") == 0) {
        cout << "Linux dpkg scan complete" << endl;
    }
    else {
        // Try rpm (Fedora / RHEL / CentOS)
        system("rpm -qa > soft_clean.txt");
        cout << "Linux rpm scan complete" << endl;
    }
    cout << "Unsupported Linux distribution (Arch, Alpine, Gentoo, Void, etc.)" << endl;
    cout << "Package scan not supported on this OS." << endl;

#endif

    return 0;
}
