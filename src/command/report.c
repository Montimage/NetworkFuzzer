#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT         "4242"
#define DEFAULT_OUTPUT_DIR   "."
#define DEFAULT_FORMAT       "html,json"
#define DEFAULT_MAX_SEQ      "3"

int report(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("report [<Option>]\n");
        printf("Generate an HTML and/or JSON security report from a fuzzing corpus directory.\n\n");
        printf("Option:\n");
        printf("\t--host <ip>            : Target host (required)\n");
        printf("\t--port <port>          : Target port (default: %s)\n", DEFAULT_PORT);
        printf("\t--corpus-dir <dir>     : Fuzzing corpus directory containing hangs/*.json\n");
        printf("\t--findings <file>      : Pre-built findings JSON (from vulnscan or previous report)\n");
        printf("\t--discovery <file>     : Discovery JSON file (optional)\n");
        printf("\t--output-dir <dir>     : Output directory for report files (default: %s)\n", DEFAULT_OUTPUT_DIR);
        printf("\t--format <fmt>         : Comma-separated formats: html,json (default: %s)\n", DEFAULT_FORMAT);
        printf("\t--max-sequences <N>    : Max attack sequences to show per finding (default: %s)\n", DEFAULT_MAX_SEQ);
        printf("\t-h                     : Print this help, then exit.\n");
        printf("\nEnvironment Variables:\n");
        printf("\tPYTHON                 : Python interpreter to use (default: python3)\n");
        printf("\t                         Example: export PYTHON=/path/to/venv/bin/python3\n");
        printf("\nExamples:\n");
        printf("\t# From fuzzing corpus (auto-classify and generate report):\n");
        printf("\treport --host 192.168.1.200 --port 4242 \\\n");
        printf("\t    --corpus-dir ./corpus_hybrid --output-dir ./reports\n");
        printf("\n\t# From pre-built findings JSON (vulnscan output):\n");
        printf("\treport --host 192.168.1.200 --port 4242 \\\n");
        printf("\t    --findings ./scan_findings.json --output-dir ./reports\n");
        printf("\n\t# With discovery info and limited sequences:\n");
        printf("\treport --host 192.168.1.200 --port 4242 \\\n");
        printf("\t    --corpus-dir ./corpus_hybrid --discovery ./discovery.json \\\n");
        printf("\t    --output-dir ./reports --max-sequences 5\n");
        return 0;
    }

    char *host        = NULL;
    char *port        = DEFAULT_PORT;
    char *corpus_dir  = NULL;
    char *findings    = NULL;
    char *discovery   = NULL;
    char *output_dir  = DEFAULT_OUTPUT_DIR;
    char *format      = DEFAULT_FORMAT;
    char *max_seq     = DEFAULT_MAX_SEQ;

    for (int i = 1; i < argc; ++i) {
        if      (strcmp(argv[i], "--host")          == 0 && i+1 < argc) host       = argv[++i];
        else if (strcmp(argv[i], "--port")          == 0 && i+1 < argc) port       = argv[++i];
        else if (strcmp(argv[i], "--corpus-dir")    == 0 && i+1 < argc) corpus_dir = argv[++i];
        else if (strcmp(argv[i], "--findings")      == 0 && i+1 < argc) findings   = argv[++i];
        else if (strcmp(argv[i], "--discovery")     == 0 && i+1 < argc) discovery  = argv[++i];
        else if (strcmp(argv[i], "--output-dir")    == 0 && i+1 < argc) output_dir = argv[++i];
        else if (strcmp(argv[i], "--format")        == 0 && i+1 < argc) format     = argv[++i];
        else if (strcmp(argv[i], "--max-sequences") == 0 && i+1 < argc) max_seq    = argv[++i];
    }

    if (!host) {
        fprintf(stderr, "[networkfuzzer:report] Error: --host is required\n");
        return 1;
    }
    if (!corpus_dir && !findings) {
        fprintf(stderr, "[networkfuzzer:report] Error: --corpus-dir or --findings is required\n");
        return 1;
    }

    const char *python = getenv("PYTHON");
    if (!python || !python[0]) python = "python3";

    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    system(mkdir_cmd);

    char cmd[4096];

    if (corpus_dir) {
        /* Use corpus_report module: auto-classify corpus → findings → HTML+JSON */
        snprintf(cmd, sizeof(cmd),
            "%s -m fuzzer.pentest.reporting.corpus_report "
            "--host %s --port %s "
            "--corpus-dir %s "
            "--output-dir %s "
            "--format %s "
            "--max-sequences %s",
            python, host, port, corpus_dir, output_dir, format, max_seq);
        if (discovery) {
            strncat(cmd, " --discovery ", sizeof(cmd) - strlen(cmd) - 1);
            strncat(cmd, discovery,       sizeof(cmd) - strlen(cmd) - 1);
        }
    } else {
        /* Use generator module directly with pre-built findings JSON */
        snprintf(cmd, sizeof(cmd),
            "%s -m fuzzer.pentest.reporting.generator "
            "--host %s --port %s "
            "--findings %s "
            "--output-dir %s "
            "--format %s",
            python, host, port, findings, output_dir, format);
        if (discovery) {
            strncat(cmd, " --discovery ", sizeof(cmd) - strlen(cmd) - 1);
            strncat(cmd, discovery,       sizeof(cmd) - strlen(cmd) - 1);
        }
    }

    printf("[networkfuzzer:report] %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "[networkfuzzer:report] Report generation failed\n");
        return ret;
    }
    printf("[networkfuzzer:report] Report written to %s\n", output_dir);
    return 0;
}
