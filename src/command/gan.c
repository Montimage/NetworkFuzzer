#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_NORMAL_CSV "fuzzer/data/normal_filtered_labeled.csv"
#define DEFAULT_ABNORMAL_CSV "fuzzer/data/abnormal_filtered_labeled.csv"
#define DEFAULT_OUTPUT_DIR "/tmp"
#define DEFAULT_TEMPLATE_PCAP "fuzzer/data/template.pcap"
#define DEFAULT_PCAP_OUTPUT_DIR "fuzzer/data/pcap_output"
#define DEFAULT_SAMPLES "1000"
#define DEFAULT_EPOCHS "100"
#define DEFAULT_BATCH_SIZE "500"
#define DEFAULT_MODE "protocol"
#define DEFAULT_STRATEGY "temperature"
#define DEFAULT_TEMPERATURE "1.5"
#define DEFAULT_MALFORMATION "0.5"
#define DEFAULT_PDU_TYPE "assoc_rq"
#define DEFAULT_FUZZ_MODE "hybrid"
#define DEFAULT_PROTOCOL "dicom"
#define DEFAULT_CALLED_AE "ORTHANC"
#define DEFAULT_CALLING_AE "FUZZER"

int gan(int argc, char **argv) {
    // Custom help
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("gan [<Option>] [<normal_csv> <malicious_csv>]\n");
        printf("Option:\n");
        printf("\t--mode <mode>          : Generation mode (default: %s)\n", DEFAULT_MODE);
        printf("\t  Modes: flow, protocol, attack (CTGAN-based)\n");
        printf("\t         byte-model (Transformer), vae (VAE)\n");
        printf("\t         rl (RL-based protocol fuzzing - supports multiple protocols)\n");
        printf("\t--attack-type <type>   : Attack profile for attack mode\n");
        printf("\t--malformed            : Apply malformation mutations to PCAPs\n");
        printf("\t--samples <N>          : Number of synthetic samples to generate (default: %s)\n", DEFAULT_SAMPLES);
        printf("\t--epochs <N>           : Number of training epochs (default: %s)\n", DEFAULT_EPOCHS);
        printf("\t--batch-size <N>       : Batch size for training (default: %s)\n", DEFAULT_BATCH_SIZE);
        printf("\t--num-flows <N>        : Number of PCAP flows to generate\n");
        printf("\t--template-pcap <file> : Template PCAP (legacy flow mode) (default: %s)\n", DEFAULT_TEMPLATE_PCAP);
        printf("\t--pcap-output <dir>    : Output directory for generated PCAPs (default: %s)\n", DEFAULT_PCAP_OUTPUT_DIR);
        printf("\t--evaluate             : Run evaluation after generation\n");
        printf("\nML model options (byte-model, vae modes):\n");
        printf("\t--strategy <name>      : Generation strategy (default: %s)\n", DEFAULT_STRATEGY);
        printf("\t  byte-model strategies: temperature, topk-error, prefix, gradient\n");
        printf("\t  vae strategies:       interpolate, boundary, walk, targeted\n");
        printf("\t--temperature <float>  : Sampling temperature for byte-model (default: %s)\n", DEFAULT_TEMPERATURE);
        printf("\t--malformation <float> : Malformation degree for VAE 0.0-1.0 (default: %s)\n", DEFAULT_MALFORMATION);
        printf("\t--model-path <path>    : Path to trained model file\n");
        printf("\t--pdu-type <type>      : PDU type to generate (default: %s)\n", DEFAULT_PDU_TYPE);
        printf("\t--data-dir <dir>       : Training data directory (for train step)\n");
        printf("\t--train                : Train model before generating\n");
        printf("\nRL fuzzing options (rl mode):\n");
        printf("\t--protocol <name>      : Protocol to fuzz (default: %s)\n", DEFAULT_PROTOCOL);
        printf("\t--fuzz-mode <mode>     : Fuzzing mode (default: %s)\n", DEFAULT_FUZZ_MODE);
        printf("\t  Modes: semantic, aggressive, state, hybrid\n");
        printf("\t--target-host <ip>     : Target server IP/hostname\n");
        printf("\t--target-port <port>   : Target port (default: protocol-specific)\n");
        printf("\t--called-ae <name>     : DICOM: Called AE title (default: %s)\n", DEFAULT_CALLED_AE);
        printf("\t--calling-ae <name>    : DICOM: Calling AE title (default: %s)\n", DEFAULT_CALLING_AE);
        printf("\t--timesteps <N>        : RL training timesteps (default: %s)\n", DEFAULT_SAMPLES);
        printf("\t--n-test <N>           : Number of test episodes (default: 10)\n");
        printf("\t--exploration <float>  : Novel combo exploration rate 0.0-1.0 (default: 0.15)\n");
        printf("\t--test                 : Run test episodes after training\n");
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
        printf("\tgan --mode byte-model --strategy temperature --temperature 1.5 --samples 50\n");
        printf("\tgan --mode vae --strategy interpolate --malformation 0.5 --samples 100\n");
        printf("\nRL Fuzzing examples:\n");
        printf("\t# DICOM hybrid fuzzing (combines semantic + aggressive + state attacks)\n");
        printf("\tgan --mode rl --protocol dicom --fuzz-mode hybrid \\\n");
        printf("\t    --target-host 192.168.1.200 --target-port 4242 \\\n");
        printf("\t    --called-ae ORTHANC --timesteps 20000 --test\n");
        printf("\n\t# DICOM semantic-only fuzzing\n");
        printf("\tgan --mode rl --fuzz-mode semantic --target-host localhost --timesteps 10000\n");
        printf("\n\t# List available protocols\n");
        printf("\tgan --mode rl --list-protocols\n");
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
    int do_train = 0;
    int i, pos_count = 0;
    char *pos_args[2] = {NULL, NULL};

    // ML model options
    char *strategy = DEFAULT_STRATEGY;
    char *temperature = DEFAULT_TEMPERATURE;
    char *malformation_degree = DEFAULT_MALFORMATION;
    char *model_path = NULL;
    char *pdu_type = DEFAULT_PDU_TYPE;
    char *data_dir = NULL;
    char *target_host = NULL;
    char *target_port = NULL;  // NULL = use protocol default

    // RL fuzzing options
    char *fuzz_protocol = DEFAULT_PROTOCOL;
    char *fuzz_mode = DEFAULT_FUZZ_MODE;
    char *called_ae = DEFAULT_CALLED_AE;
    char *calling_ae = DEFAULT_CALLING_AE;
    char *n_test = "10";
    char *exploration_rate = "0.15";
    int do_test = 0;
    int list_protocols = 0;

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
        } else if (strcmp(argv[i], "--train") == 0) {
            do_train = 1;
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
        } else if (strcmp(argv[i], "--strategy") == 0 && i+1 < argc) {
            strategy = argv[++i];
        } else if (strcmp(argv[i], "--temperature") == 0 && i+1 < argc) {
            temperature = argv[++i];
        } else if (strcmp(argv[i], "--malformation") == 0 && i+1 < argc) {
            malformation_degree = argv[++i];
        } else if (strcmp(argv[i], "--model-path") == 0 && i+1 < argc) {
            model_path = argv[++i];
        } else if (strcmp(argv[i], "--pdu-type") == 0 && i+1 < argc) {
            pdu_type = argv[++i];
        } else if (strcmp(argv[i], "--data-dir") == 0 && i+1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(argv[i], "--target-host") == 0 && i+1 < argc) {
            target_host = argv[++i];
        } else if (strcmp(argv[i], "--target-port") == 0 && i+1 < argc) {
            target_port = argv[++i];
        } else if (strcmp(argv[i], "--protocol") == 0 && i+1 < argc) {
            fuzz_protocol = argv[++i];
        } else if (strcmp(argv[i], "--fuzz-mode") == 0 && i+1 < argc) {
            fuzz_mode = argv[++i];
        } else if (strcmp(argv[i], "--called-ae") == 0 && i+1 < argc) {
            called_ae = argv[++i];
        } else if (strcmp(argv[i], "--calling-ae") == 0 && i+1 < argc) {
            calling_ae = argv[++i];
        } else if (strcmp(argv[i], "--timesteps") == 0 && i+1 < argc) {
            samples = argv[++i];  // Reuse samples for timesteps
        } else if (strcmp(argv[i], "--n-test") == 0 && i+1 < argc) {
            n_test = argv[++i];
        } else if (strcmp(argv[i], "--exploration") == 0 && i+1 < argc) {
            exploration_rate = argv[++i];
        } else if (strcmp(argv[i], "--test") == 0) {
            do_test = 1;
        } else if (strcmp(argv[i], "--list-protocols") == 0) {
            list_protocols = 1;
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

    // =========================================================================
    // ML modes: byte-model, vae, rl — dispatch to Python modules
    // =========================================================================
    if (strcmp(mode, "byte-model") == 0 || strcmp(mode, "vae") == 0 || strcmp(mode, "rl") == 0) {
        char ml_cmd[4096];
        int ret;

        // Default data dir if not specified
        if (!data_dir) {
            snprintf(ml_cmd, sizeof(ml_cmd), "fuzzer/data/training_data/pdus/%s", pdu_type);
            data_dir = strdup(ml_cmd);
        }

        snprintf(ml_cmd, sizeof(ml_cmd), "mkdir -p %s fuzzer/data/models", pcap_output_dir);
        system(ml_cmd);

        if (strcmp(mode, "byte-model") == 0) {
            // Default model path
            if (!model_path) {
                snprintf(ml_cmd, sizeof(ml_cmd), "fuzzer/data/models/%s_transformer.pt", pdu_type);
                model_path = strdup(ml_cmd);
            }

            // Train if requested
            if (do_train) {
                snprintf(ml_cmd, sizeof(ml_cmd),
                    "%s -m fuzzer.models.byte_model.train --data-dir %s --epochs %s "
                    "--batch-size %s --max-length 256 --model-out %s",
                    python, data_dir, epochs, batch_size, model_path);
                printf("[networkfuzzer:gan] Training: %s\n", ml_cmd);
                ret = system(ml_cmd);
                if (ret != 0) { fprintf(stderr, "[networkfuzzer:gan] Training failed\n"); return ret; }
            }

            // Generate
            snprintf(ml_cmd, sizeof(ml_cmd),
                "%s -m fuzzer.models.byte_model.generate --model %s --count %s "
                "--strategy %s --temp %s --output-dir %s --to-pcap",
                python, model_path, samples, strategy, temperature, pcap_output_dir);
            printf("[networkfuzzer:gan] Generating: %s\n", ml_cmd);
            ret = system(ml_cmd);

        } else if (strcmp(mode, "vae") == 0) {
            if (!model_path) {
                snprintf(ml_cmd, sizeof(ml_cmd), "fuzzer/data/models/%s_vae.pt", pdu_type);
                model_path = strdup(ml_cmd);
            }

            if (do_train) {
                snprintf(ml_cmd, sizeof(ml_cmd),
                    "%s -m fuzzer.models.vae_model.train --data-dir %s --epochs %s "
                    "--batch-size %s --model-out %s",
                    python, data_dir, epochs, batch_size, model_path);
                printf("[networkfuzzer:gan] Training: %s\n", ml_cmd);
                ret = system(ml_cmd);
                if (ret != 0) { fprintf(stderr, "[networkfuzzer:gan] Training failed\n"); return ret; }
            }

            snprintf(ml_cmd, sizeof(ml_cmd),
                "%s -m fuzzer.models.vae_model.latent_explorer --model %s --data-dir %s "
                "--strategy %s --degree %s --count %s --output-dir %s --to-pcap",
                python, model_path, data_dir, strategy, malformation_degree,
                samples, pcap_output_dir);
            printf("[networkfuzzer:gan] Generating: %s\n", ml_cmd);
            ret = system(ml_cmd);

        } else if (strcmp(mode, "rl") == 0) {
            // Handle --list-protocols
            if (list_protocols) {
                snprintf(ml_cmd, sizeof(ml_cmd),
                    "%s -m fuzzer.rl.train_protocol --list-protocols",
                    python);
                printf("[networkfuzzer:gan] %s\n", ml_cmd);
                ret = system(ml_cmd);
                return ret;
            }

            if (!model_path) {
                snprintf(ml_cmd, sizeof(ml_cmd), "fuzzer/data/models/rl_%s_%s",
                         fuzz_protocol, fuzz_mode);
                model_path = strdup(ml_cmd);
            }

            // Use new protocol-agnostic trainer
            snprintf(ml_cmd, sizeof(ml_cmd),
                "%s -m fuzzer.rl.train_protocol "
                "--protocol %s --mode %s "
                "--timesteps %s --model-out %s --output-dir %s",
                python, fuzz_protocol, fuzz_mode,
                samples, model_path, pcap_output_dir);

            // Add target if specified
            if (target_host) {
                char extra[512];
                if (target_port) {
                    snprintf(extra, sizeof(extra), " --target-host %s --target-port %s",
                             target_host, target_port);
                } else {
                    snprintf(extra, sizeof(extra), " --target-host %s", target_host);
                }
                strcat(ml_cmd, extra);
            }

            // Add DICOM-specific options
            if (strcmp(fuzz_protocol, "dicom") == 0) {
                char dicom_opts[256];
                snprintf(dicom_opts, sizeof(dicom_opts),
                         " --called-ae %s --calling-ae %s",
                         called_ae, calling_ae);
                strcat(ml_cmd, dicom_opts);
            }

            // Add exploration rate
            if (exploration_rate && strcmp(exploration_rate, "0.15") != 0) {
                char explore_opts[64];
                snprintf(explore_opts, sizeof(explore_opts), " --exploration-rate %s", exploration_rate);
                strcat(ml_cmd, explore_opts);
            }

            // Add test options
            if (do_test) {
                char test_opts[128];
                snprintf(test_opts, sizeof(test_opts), " --test --n-test %s", n_test);
                strcat(ml_cmd, test_opts);
            }

            printf("[networkfuzzer:gan] RL fuzzing: %s\n", ml_cmd);
            ret = system(ml_cmd);
        }

        if (ret != 0) {
            fprintf(stderr, "[networkfuzzer:gan] ML generation failed\n");
            return ret;
        }

        printf("[networkfuzzer:gan] ML generation complete.\n");
        printf("[networkfuzzer:gan] Mode: %s, Strategy: %s\n", mode, strategy);
        printf("[networkfuzzer:gan] PCAPs: %s\n", pcap_output_dir);
        return 0;
    }

    // =========================================================================
    // CTGAN modes: flow, protocol, attack — existing pipeline
    // =========================================================================

    // Step 1: Run GAN
    char gan_cmd[4096];
    snprintf(gan_cmd, sizeof(gan_cmd),
        "%s fuzzer/gan/gan.py --mode %s --samples %s --epochs %s --batch-size %s",
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
        "%s fuzzer/gan/synthetic_to_pcap.py %s %s",
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
            "%s fuzzer/gan/evaluate_feature_similarity.py %s %s %s",
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
