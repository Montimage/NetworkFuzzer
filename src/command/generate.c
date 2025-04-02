/*
 * generate.c
 *
 * Implements the command to generate DICOM fuzzing rules
 * by invoking the Python rule generator script.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h> /* for dirname() */
#include <sys/stat.h> /* for stat() */

#include "../lib/mmt_lib.h"

static void _usage(const char *prog) {
    fprintf(stderr, "%s [<option>] \"prompt\"\n", prog);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-h             : Prints this help then exit\n");
    fprintf(stderr, "\t-s             : Save the generated rule to a file in the rules directory\n");
    fprintf(stderr, "\t-o <filename>  : Specify output filename for the generated rule (implies -s)\n");
    fprintf(stderr, "\t-m <model>     : Specify OpenAI model to use. Default: gpt-4\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "\t%s \"Generate a rule that tests invalid PDU lengths\"\n", prog);
    fprintf(stderr, "\t%s -s \"Create a rule to fuzz Calling AE Titles\"\n", prog);
    fprintf(stderr, "\t%s -s -o my_rule.xml \"Make a rule that sends invalid PDU types\"\n", prog);
}

// Find base directory of NetworkFuzzer
static char* get_install_dir() {
    static char path[512] = {0};
    if (path[0] == '\0') {
        // First try to find the executable path
        if (readlink("/proc/self/exe", path, sizeof(path) - 1) == -1) {
            // If readlink fails, use current directory
            if (getcwd(path, sizeof(path) - 1) == NULL) {
                strcpy(path, ".");
                return path;
            }
        }

        // Extract directory containing the executable
        char *dir = dirname(path);
        // Get parent directory (NetworkFuzzer base dir)
        snprintf(path, sizeof(path), "%s", dir);
        char *parent = dirname(path);

        // Try standard locations if not found
        struct stat st;
        char test_path[512];
        snprintf(test_path, sizeof(test_path), "%s/utils/llm_rule_gen", parent);

        if (stat(test_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            // Found the utils/llm_rule_gen directory in parent of executable
            snprintf(path, sizeof(path), "%s", parent);
        } else {
            // Check if the script is in the current directory's parent
            if (getcwd(path, sizeof(path) - 1) != NULL) {
                parent = dirname(path);
                snprintf(test_path, sizeof(test_path), "%s/utils/llm_rule_gen", parent);
                if (stat(test_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                    snprintf(path, sizeof(path), "%s", parent);
                } else {
                    // Last resort: assume current directory is NetworkFuzzer base
                    if (getcwd(path, sizeof(path) - 1) == NULL) {
                        strcpy(path, ".");
                    }
                }
            }
        }
    }
    return path;
}

int generate(int argc, char **argv) {
    int opt;
    int save_flag = 0;
    char *output_file = NULL;
    char *model = "gpt-4";
    char command[4096] = "";
    char script_path[512] = "";

    // Parse command line options
    while ((opt = getopt(argc, argv, "hso:m:")) != EOF) {
        switch (opt) {
            case 'h':
                _usage(argv[0]);
                return EXIT_SUCCESS;
            case 's':
                save_flag = 1;
                break;
            case 'o':
                output_file = optarg;
                save_flag = 1; // If output file is specified, assume save is wanted
                break;
            case 'm':
                model = optarg;
                break;
            default:
                _usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    // Get the prompt argument (if provided)
    char *prompt = NULL;
    if (optind < argc) {
        prompt = argv[optind];
    }

    // If no prompt, show usage
    if (!prompt) {
        _usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Determine the script path - look for it in NetworkFuzzer's utils directory
    char *install_dir = get_install_dir();
    snprintf(script_path, sizeof(script_path), "%s/utils/llm_rule_gen/dicom_rule_generator.py", install_dir);

    // Check if the script exists
    if (access(script_path, F_OK) == -1) {
        fprintf(stderr, "Error: Rule generator script not found at: %s\n", script_path);
        //fprintf(stderr, "Please ensure the Python script is installed in the utils/llm_rule_gen directory.\n");
        return EXIT_FAILURE;
    }

    // Check for OPENAI_API_KEY environment variable or .env file
    char env_file_path[512];
    snprintf(env_file_path, sizeof(env_file_path), "%s/utils/llm_rule_gen/.env", get_install_dir());

    // Check if .env file exists
    int env_file_exists = (access(env_file_path, F_OK) != -1);

    // If API key not in env vars and .env file doesn't exist, show error
    if (getenv("OPENAI_API_KEY") == NULL && !env_file_exists) {
        fprintf(stderr, "Error: OPENAI_API_KEY environment variable not set and .env file not found.\n");
        fprintf(stderr, "Please set your OpenAI API key using one of these methods:\n");
        fprintf(stderr, "1. Create a .env file at %s with your API key\n", env_file_path);
        fprintf(stderr, "2. Set the environment variable: export OPENAI_API_KEY='your-api-key-here'\n");
        fprintf(stderr, "\nSee utils/llm_rule_gen/README.md for more information.\n");
        return EXIT_FAILURE;
    }

    // Build the command
    strcpy(command, "python3 ");
    strcat(command, script_path);

    if (save_flag) {
        strcat(command, " --save");

        // If output_file is not specified, but save is requested,
        // set default output directory to ./rules/
        if (!output_file) {
            char rules_dir[512];
            snprintf(rules_dir, sizeof(rules_dir), "%s/rules", get_install_dir());

            // Check if rules directory exists, create it if it doesn't
            struct stat st;
            if (stat(rules_dir, &st) == -1) {
                if (mkdir(rules_dir, 0755) == -1) {
                    log_write(LOG_WARNING, "Could not create rules directory at %s: %s",
                          rules_dir, strerror(errno));
                } else {
                    log_write(LOG_INFO, "Created rules directory at %s", rules_dir);
                }
            }
        }
    }

    if (output_file) {
        // If path is relative and doesn't start with "rules/", prepend "rules/"
        if (output_file[0] != '/' && strncmp(output_file, "rules/", 6) != 0) {
            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s", output_file);  // No rules/ prefix - Python script adds it
            strcat(command, " --output \"");
            strcat(command, full_path);
            strcat(command, "\"");
        } else {
            strcat(command, " --output \"");
            strcat(command, output_file);
            strcat(command, "\"");
        }
    }

    if (model) {
        strcat(command, " --model \"");
        strcat(command, model);
        strcat(command, "\"");
    }

    if (prompt) {
        strcat(command, " \"");
        strcat(command, prompt);
        strcat(command, "\"");
    }

    int status = system(command);

    if (status == -1) {
        log_write(LOG_ERR, "Failed to execute command: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status != 0) {
            log_write(LOG_ERR, "Command exited with status %d", exit_status);
            return EXIT_FAILURE;
        } else {
            // Success message
            if (save_flag) {
                printf("\nYou can now use 'networkfuzzer compile' to compile the rule.\n");
            } else {
                printf("\nRule generated successfully.\n");
                printf("Use -s option to save the rule to a file for later use.\n");
            }
        }
    } else {
        log_write(LOG_ERR, "Command terminated abnormally");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}