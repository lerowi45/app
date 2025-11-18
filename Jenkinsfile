pipeline {
    agent { label 'DevSecOps-Agent' }

    environment {
        GITHUB_REPO = 'git@github.com:lerowi45/app.git'
    }

    stages {
        stage('Clone') {
            steps {
                echo "📥 Cloning repository..."
                git credentialsId: 'git_auth_ssh_key', url: "${GITHUB_REPO}", branch: 'main'
            }
        }

        stage('Parallel Secrets Scan') {
            parallel {
                stage('DetectSecrets') {
                    steps {
                        sh '''#!/bin/bash
                        set -euo pipefail

                        echo "🔍 Checking if Python3 is installed..."
                        if ! command -v python3 &> /dev/null; then
                            echo "Python3 not found. Installing..."
                            sudo apt update -y
                            sudo apt install -y python3 python3-venv python3-pip
                        fi

                        echo "🐍 Setting up virtual environment..."
                        python3 -m venv venv
                        source venv/bin/activate

                        echo "📦 Installing dependencies..."
                        pip install "detect-secrets==1.5.0"
                        pip install --quiet jq

                        echo "🔎 Checking for .secrets.baseline..."
                        if [ ! -f .secrets.baseline ]; then
                            echo "⚠️ No existing .secrets.baseline file detected. Creating new blank baseline..."
                            mkdir -p empty-dir
                            detect-secrets scan empty-dir > .secrets.baseline
                            rm -rf empty-dir
                            echo "✅ Blank .secrets.baseline file created."
                        else
                            echo "✅ Existing .secrets.baseline file detected."
                        fi

                        echo "🧭 Scanning repository for secrets..."
                        detect-secrets scan --baseline .secrets.baseline \
                                            --exclude-files '.secrets.*' \
                                            --exclude-files '.git*' \
                                            > .secrets.new

                        baseline_1=".secrets.baseline"
                        baseline_2=".secrets.new"

                        if [[ ! -f "$baseline_1" || ! -f "$baseline_2" ]]; then
                            echo "❌ Missing baseline file(s)"
                            exit 1
                        fi

                        echo "🔍 Comparing baselines..."
                        if ! diff <(jq -r '.results | to_entries[] | "\\(.key),\\(.value[]?.hashed_secret)"' "$baseline_1" | sort) \
                                 <(jq -r '.results | to_entries[] | "\\(.key),\\(.value[]?.hashed_secret)"' "$baseline_2" | sort) \
                                 >/dev/null; then
                            echo "⚠️ Attention Required! ⚠️"
                            echo "New secrets have been detected in your recent commit."
                            echo ""
                            echo "🧭 Please follow these steps locally to clean up secrets:"
                            echo "1️⃣ Run: detect-secrets scan > .secrets.baseline"
                            echo "2️⃣ Review: detect-secrets audit .secrets.baseline"
                            echo "3️⃣ Remove or mask detected secrets."
                            echo "4️⃣ Commit and push your changes again."
                            echo ""
                            echo "🔗 Docs: https://nasa-ammos.github.io/slim/continuous-testing/starter-kits/#detect-secrets"
                            rm -f .secrets.new && rm -f baseline_2
                            exit 1
                        else
                            echo "✅ Great! No new secrets found."
                        fi
                        deactivate || true
                        exit 0
                        '''
                    }
                    
                }
                stage('Trufflehog') {
                    steps {
                        sh '''#!/bin/bash
                        echo "📦Installing Trufflehog"
                        # install with script
                        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin

                        echo "🧭 Running TruffleHog scan..."

                        # Fail immediately on any non-zero exit code
                        set -e  

                        # Run TruffleHog, save full JSON output to file
                        trufflehog filesystem . -x exclude.txt --fail --no-update --json > trufflehog_output.json || EXIT_CODE=$?

                        # If secrets found (exit code 183) or other errors
                        if [ "${EXIT_CODE:-0}" -eq 183 ]; then
                        echo "❌ Trufflehog detected secrets!"

                        # Parse line-by-line JSON safely
                        while IFS= read -r line; do
                            echo "$line" | jq -r '
                            {
                            file: .SourceMetadata.Data.Filesystem.file,
                            line_number: .SourceMetadata.Data.Filesystem.line,
                            detector: .DetectorName,
                            line_preview: "***REDACTED***",
                            rotation_guide: .ExtraData.rotation_guide
                            }'
                        done < trufflehog_output.json

                        exit 1
                    elif [ "${EXIT_CODE:-0}" -ne 0 ]; then
                        echo "⚠️ TruffleHog encountered an error during scanning!"
                        cat trufflehog_output.json
                        exit 1
                    else
                        echo "✅ Nice! No secrets found."
                    fi
                    '''
                    }
                }
            }
        }
    }

    post {
        always {
            echo "🧹 Cleaning up virtual environment..."
            sh '''
            rm -rf venv || true
            rm -f trufflehog_output.json || true
            '''
        }
        failure {
            echo "🚨 Secrets scan failed. Review the logs for details."
        }
        success {
            echo "✅ Pipeline completed successfully — no secrets found."
        }
    }
}
