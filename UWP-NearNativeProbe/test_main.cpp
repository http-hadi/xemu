// Console harness: builds the same probes.cpp for desktop Windows / Wine so the
// logic can be exercised before it goes into the UWP package.
#include "probes.h"
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    nn::SetLogFile(stdout);
    nn::SetStateDir(L".");
    nn::ResolveCrashedTests();
    bool danger = argc > 1 && !strcmp(argv[1], "danger");
    bool safe = !(argc > 1 && !strcmp(argv[1], "danger-only"));
    if (safe && !danger)
        nn::RunSafeProbes();
    if (danger || (argc > 1 && !strcmp(argv[1], "danger-only")))
        nn::RunDangerous();
    nn::ReportDangerousState();
    printf("\n--- SUMMARY ---\n");
    for (const auto &s : nn::Summary())
        puts(s.c_str());
    return 0;
}
