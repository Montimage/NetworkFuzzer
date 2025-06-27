#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_NORMAL_CSV "GAN/normal_filtered_labeled.csv"
#define DEFAULT_ABNORMAL_CSV "GAN/abnormal_filtered_labeled.csv"
#define DEFAULT_OUTPUT_DIR "/tmp"
#define DEFAULT_TEMPLATE_PCAP "GAN/template.pcap"
#define DEFAULT_PCAP_OUTPUT_DIR "GAN/pcap_output"
#define DEFAULT_SAMPLES "1000"
#define DEFAULT_EPOCHS "100"
#define DEFAULT_BATCH_SIZE "500"

// Helper to check if an argument is present
static int has_arg(int argc, char **argv, const char *arg) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], arg) == 0) return 1;
    }
    return 0;
}

int gan(int argc, char **argv) {
    // Custom help
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("gan [<Option>] [<normal_csv> <malicious_csv>]\n");
        printf("Option:\n");
        printf("\t--samples <N>          : Number of synthetic samples to generate (default: %s)\n", DEFAULT_SAMPLES);
        printf("\t--epochs <N>           : Number of training epochs (default: %s)\n", DEFAULT_EPOCHS);
        printf("\t--batch-size <N>       : Batch size for training (default: %s)\n", DEFAULT_BATCH_SIZE);
        printf("\t--synthetic-features <list> : Comma-separated features to synthesize\n");
        printf("\t--template-pcap <file> : Template PCAP file for synthetic_to_pcap.py (default: %s)\n", DEFAULT_TEMPLATE_PCAP);
        printf("\t--pcap-output <dir>    : Output directory for generated PCAPs (default: %s)\n", DEFAULT_PCAP_OUTPUT_DIR);
        printf("\t-h               : Prints this help, then exits.\n");
        printf("\nArguments:\n");
        printf("\tnormal_csv             : Path to normal flows CSV (default: %s)\n", DEFAULT_NORMAL_CSV);
        printf("\tmalicious_csv          : Path to malicious flows CSV (default: %s)\n", DEFAULT_ABNORMAL_CSV);
        printf("\nNote: Output directory for synthetic CSVs is always %s.\n", DEFAULT_OUTPUT_DIR);
        printf("\nExample:\n");
        printf("\tgan --template-pcap %s --pcap-output %s\n", DEFAULT_TEMPLATE_PCAP, DEFAULT_PCAP_OUTPUT_DIR);
        printf("\tgan %s %s --samples 5000 --epochs 200 --batch-size 1000 --template-pcap %s --pcap-output %s\n",
            DEFAULT_NORMAL_CSV, DEFAULT_ABNORMAL_CSV, DEFAULT_TEMPLATE_PCAP, DEFAULT_PCAP_OUTPUT_DIR);
        return 0;
    }

    // Defaults
    char *normal_csv = DEFAULT_NORMAL_CSV;
    char *abnormal_csv = DEFAULT_ABNORMAL_CSV;
    char *output_dir = DEFAULT_OUTPUT_DIR;
    char *template_pcap = DEFAULT_TEMPLATE_PCAP;
    char *pcap_output_dir = DEFAULT_PCAP_OUTPUT_DIR;
    char *samples = DEFAULT_SAMPLES;
    char *epochs = DEFAULT_EPOCHS;
    char *batch_size = DEFAULT_BATCH_SIZE;
    char *synthetic_features = NULL;
    char gan_cmd[2048] = "python3 GAN/gan.py";
    int i, pos_count = 0;
    char *pos_args[2] = {NULL, NULL};

    // Parse options and positional arguments
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--template-pcap") == 0 && i+1 < argc) {
            template_pcap = argv[++i];
        } else if (strcmp(argv[i], "--pcap-output") == 0 && i+1 < argc) {
            pcap_output_dir = argv[++i];
        } else if (strcmp(argv[i], "--samples") == 0 && i+1 < argc) {
            samples = argv[++i];
        } else if (strcmp(argv[i], "--epochs") == 0 && i+1 < argc) {
            epochs = argv[++i];
        } else if (strcmp(argv[i], "--batch-size") == 0 && i+1 < argc) {
            batch_size = argv[++i];
        } else if (strcmp(argv[i], "--synthetic-features") == 0 && i+1 < argc) {
            synthetic_features = argv[++i];
        } else if (argv[i][0] != '-' && pos_count < 2) {
            pos_args[pos_count++] = argv[i];
        }
    }

    if (pos_count >= 1) normal_csv = pos_args[0];
    if (pos_count == 2) abnormal_csv = pos_args[1];

    // Ensure output_dir exists
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    int mkret = system(mkdir_cmd);
    if (mkret != 0) {
        fprintf(stderr, "[networkfuzzer:gan] Failed to create output directory: %s\n", output_dir);
        return mkret;
    }

    // Step 1: Run GAN
    snprintf(gan_cmd, sizeof(gan_cmd),
        "python3 GAN/gan.py --samples %s --epochs %s --batch-size %s",
        samples, epochs, batch_size);
    if (synthetic_features) {
        strcat(gan_cmd, " --synthetic-features ");
        strcat(gan_cmd, synthetic_features);
    }
    strcat(gan_cmd, " ");
    strcat(gan_cmd, normal_csv);
    strcat(gan_cmd, " ");
    strcat(gan_cmd, abnormal_csv);
    strcat(gan_cmd, " ");
    strcat(gan_cmd, output_dir);
    printf("[networkfuzzer:gan] Running: %s\n", gan_cmd);
    int ret = system(gan_cmd);
    if (ret != 0) {
        fprintf(stderr, "[networkfuzzer:gan] gan.py failed\n");
        return ret;
    }

    // Step 2: Find the latest synthetic CSV in output_dir
    char find_csv_cmd[1024];
    char csv_path[512] = "";
    snprintf(find_csv_cmd, sizeof(find_csv_cmd),
        "ls -1t %s/*dicom_flows_*.csv 2>/dev/null | head -n 1", output_dir);
    FILE *fp = popen(find_csv_cmd, "r");
    if (fp) {
        if (fgets(csv_path, sizeof(csv_path), fp) == NULL) {
            fprintf(stderr, "[networkfuzzer:gan] Error: No synthetic CSV found in %s\n", output_dir);
            pclose(fp);
            return 1;
        }
        pclose(fp);
        // Remove trailing newline
        size_t len = strlen(csv_path);
        if (len > 0 && csv_path[len-1] == '\n') csv_path[len-1] = '\0';
    } else {
        fprintf(stderr, "[networkfuzzer:gan] Error: Could not search for synthetic CSV in %s\n", output_dir);
        return 1;
    }

    // Ensure pcap_output_dir exists
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", pcap_output_dir);
    mkret = system(mkdir_cmd);
    if (mkret != 0) {
        fprintf(stderr, "[networkfuzzer:gan] Failed to create pcap output directory: %s\n", pcap_output_dir);
        return mkret;
    }

    // Step 3: Run synthetic_to_pcap.py
    char pcap_cmd[2048];
    snprintf(pcap_cmd, sizeof(pcap_cmd),
        "python3 GAN/synthetic_to_pcap.py %s %s %s",
        template_pcap, csv_path, pcap_output_dir);
    printf("[networkfuzzer:gan] Running: %s\n", pcap_cmd);
    ret = system(pcap_cmd);
    if (ret != 0) {
        fprintf(stderr, "[networkfuzzer:gan] synthetic_to_pcap.py failed\n");
        return ret;
    }

    printf("[networkfuzzer:gan] Synthetic data and PCAP generation complete.\n");
    return 0;
}