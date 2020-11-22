set -e
rm -rf qldb
make clean
codeql database create qldb --language=cpp --command make
codeql database upgrade qldb
codeql query run ~/projects/vscode-codeql-starter/codeql-custom-queries-cpp/example.ql -d ./qldb

