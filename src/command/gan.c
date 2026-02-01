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
#define DEFAULT_MODE "protocol"

int gan(int argc, char **argv) {
    // Custom help
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("gan [<Option>] [<normal_csv> <malicious_csv>]\n");
        printf("Option:\n");
        printf("\t--mode <flow|protocol|attack> : Generation mode (default: %s)\n", DEFAULT_MODE);
        printf("\t--attack-type <type>   : Attack profile for attack mode\n");
        printf("\t--malformed            : Apply malformation mutations to PCAPs\n");
        printf("\t--samples <N>          : Number of synthetic samples to generate (default: %s)\n", DEFAULT_SAMPLES);
        printf("\t--epochs <N>           : Number of training epochs (default: %s)\n", DEFAULT_EPOCHS);
        printf("\t--batch-size <N>       : Batch size for training (default: %s)\n", DEFAULT_BATCH_SIZE);
        printf("\t--num-flows <N>        : Number of PCAP flows to generate\n");
        printf("\t--template-pcap <file> : Template PCAP (legacy flow mode) (default: %s)\n", DEFAULT_TEMPLATE_PCAP);
        printf("\t--pcap-output <dir>    : Output directory for generated PCAPs (default: %s)\n", DEFAULT_PCAP_OUTPUT_DIR);
        printf("\t--evaluate             : Run evaluation after generation\n");
        printf("\t-h                     : Prints this help, then exits.\n");
        printf("\nArguments:\n");
        printf("\tnormal_csv             : Path to normal flows CSV (default: %s)\n", DEFAULT_NORMAL_CSV);
        printf("\tmalicious_csv          : Path to malicious flows CSV (default: %s)\n", DEFAULT_ABNORMAL_CSV);
        printf("\nAttack types:\n");
        printf("\tabort_injection, state_confusion, ae_manipulation, pdu_length_attack,\n");
        printf("\tcve_payloads, association_flood, patient_enum, patient_data_injection,\n");
        printf("\timaging_manipulation\n");
        printf("\nExamples:\n");
        printf("\tgan --mode protocol --samples 500 --epochs 200\n");
        printf("\tgan --mode attack --attack-type ae_manipulation --samples 50\n");
        printf("\tgan --mode attack --attack-type abort_injection --malformed --samples 100\n");
        return 0;
    }

    // Defaults
    char *normal_csv = DEFAULT_NORMAL_CSV;
    char *abnormal_csv = DEFAULT_ABNORMAL_CSV;
    char *output_dir = DEFAULT_OUTPUT_DIR;
    char *pcap_output_dir = DEFAULT_PCAP_OUTPUT_DIR;
    char *samples = DEFAULT_SAMPLES;
    char *epochs = DEFAULT_EPOCHS;
    char *batch_size = DEFAULT_BATCH_SIZE;
    char *mode = DEFAULT_MODE;
    char *attack_type = NULL;
    char *num_flows = NULL;
    int malformed = 0;
    int evaluate = 0;
    int i, pos_count = 0;
    char *pos_args[2] = {NULL, NULL};

    // Parse options and positional arguments
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mode") == 0 && i+1 < argc) {
            mode = argv[++i];
        } else if (strcmp(argv[i], "--attack-type") == 0 && i+1 < argc) {
            attack_type = argv[++i];
        } else if (strcmp(argv[i], "--malformed") == 0) {
            malformed = 1;
        } else if (strcmp(argv[i], "--evaluate") == 0) {
            evaluate = 1;
        } else if (strcmp(argv[i], "--template-pcap") == 0 && i+1 < argc) {
            ++i; // accepted for backward compat, unused in protocol/attack modes
        } else if (strcmp(argv[i], "--pcap-output") == 0 && i+1 < argc) {
            pcap_output_dir = argv[++i];
        } else if (strcmp(argv[i], "--samples") == 0 && i+1 < argc) {
            samples = argv[++i];
        } else if (strcmp(argv[i], "--epochs") == 0 && i+1 < argc) {
            epochs = argv[++i];
        } else if (strcmp(argv[i], "--batch-size") == 0 && i+1 < argc) {
            batch_size = argv[++i];
        } else if (strcmp(argv[i], "--num-flows") == 0 && i+1 < argc) {
            num_flows = argv[++i];
        } else if (argv[i][0] != '-' && pos_count < 2) {
            pos_args[pos_count++] = argv[i];
        }
    }

    if (pos_count >= 1) normal_csv = pos_args[0];
    if (pos_count == 2) abnormal_csv = pos_args[1];

    // Ensure output directories exist
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    int mkret = system(mkdir_cmd);
    if (mkret != 0) {
        fprintf(stderr, "[networkfuzzer:gan] Failed to create output directory: %s\n", output_dir);
        return mkret;
    }

    // Use PYTHON env var if set, otherwise default to python3
    const char *python = getenv("PYTHON");
    if (!python || !python[0]) python = "python3";

    // Step 1: Run GAN
    char gan_cmd[4096];
    snprintf(gan_cmd, sizeof(gan_cmd),
        "%s GAN/gan.py --mode %s --samples %s --epochs %s --batch-size %s",
        python, mode, samples, epochs, batch_size);
    if (attack_type) {
        strcat(gan_cmd, " --attack-type ");
        strcat(gan_cmd, attack_type);
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
        "ls -1t %s/*dicom_*flows_*.csv 2>/dev/null | head -n 1", output_dir);
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
    char pcap_cmd[4096];
    snprintf(pcap_cmd, sizeof(pcap_cmd),
        "%s GAN/synthetic_to_pcap.py %s %s",
        python, csv_path, pcap_output_dir);
    if (attack_type) {
        strcat(pcap_cmd, " --attack-type ");
        strcat(pcap_cmd, attack_type);
    }
    if (malformed) {
        strcat(pcap_cmd, " --malformed");
    }
    if (num_flows) {
        strcat(pcap_cmd, " --num-flows ");
        strcat(pcap_cmd, num_flows);
    }

    printf("[networkfuzzer:gan] Running: %s\n", pcap_cmd);
    ret = system(pcap_cmd);
    if (ret != 0) {
        fprintf(stderr, "[networkfuzzer:gan] synthetic_to_pcap.py failed\n");
        return ret;
    }

    // Step 4: Optionally run evaluation
    if (evaluate) {
        char eval_cmd[4096];
        snprintf(eval_cmd, sizeof(eval_cmd),
            "%s GAN/evaluate_feature_similarity.py %s %s %s",
            python, abnormal_csv, csv_path, pcap_output_dir);
        if (attack_type) {
            snprintf(eval_cmd + strlen(eval_cmd), sizeof(eval_cmd) - strlen(eval_cmd),
                " --pcap-dir %s --attack-type %s",
                pcap_output_dir, attack_type);
        }
        printf("[networkfuzzer:gan] Running: %s\n", eval_cmd);
        ret = system(eval_cmd);
        if (ret != 0) {
            fprintf(stderr, "[networkfuzzer:gan] evaluation failed (non-fatal)\n");
            // Non-fatal: continue
        }
    }

    printf("[networkfuzzer:gan] Synthetic data and PCAP generation complete.\n");
    printf("[networkfuzzer:gan] Mode: %s\n", mode);
    if (attack_type) printf("[networkfuzzer:gan] Attack type: %s\n", attack_type);
    if (malformed) printf("[networkfuzzer:gan] Malformations applied\n");
    printf("[networkfuzzer:gan] PCAPs: %s\n", pcap_output_dir);
    return 0;
}
