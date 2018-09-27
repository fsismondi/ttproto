properties([[$class: 'GitLabConnectionProperty', gitLabConnection: 'figitlab']])

if(env.JOB_NAME =~ 'ttproto-unittest/'){
    node('docker'){

        env.TEST_FILE_TAT_COAP_COMMON="tests/test_tat/test_common.py"
        env.TEST_FILE_TAT_COAP_CORE="tests/test_tat/test_tat_coap_core.py"
        env.TEST_FILE_TAT_COAP_OBSERVE="tests/test_tat/test_tat_coap_observe.py"
        env.TEST_FILE_TAT_COAP_BLOCK="tests/test_tat/test_tat_coap_block.py"
        env.TEST_FILE_DISSECTOR_TESTS="tests/test_core/test_dissector/"
        env.TEST_FILE_ANALYZER_TESTS="tests/test_core/test_analyzer/"

        stage ("Setup dependencies"){
            checkout scm
            sh 'git submodule update --init'
            withEnv(["DEBIAN_FRONTEND=noninteractive"]){
                sh '''
                    sudo apt-get clean
                    sudo apt-get update
                    sudo apt-get upgrade -y
                    sudo apt-get install --fix-missing -y python3-dev python3-pip python3-setuptools
                    sudo -H python3 -m pip install --user --upgrade pip
                '''

            /* Show deployed code */
            /* sh "tree ." */
          }
      }

      stage("check python version"){
        sh '''
            python3 --version
        '''
      }

      stage("virtualenv and requirements installs"){
            withEnv(["DEBIAN_FRONTEND=noninteractive"]){
                sh '''
                    python3 -m pip install --user virtualenv
                    python3 -m virtualenv -p python3 /tmp/venv
                    . /tmp/venv/bin/activate
                    python3 -m pip install pytest --ignore-installed
                    python3 -m pip install -r requirements.txt --upgrade
                '''
            }
      }

      stage("TAT frames-pre-processing unittesting"){
            sh '''
                . /tmp/venv/bin/activate
                python3 -m unittest $TEST_FILE_TAT_COAP_COMMON -vvv
            '''
      }

      stage("TAT CoAP unittesting"){
            sh '''
                . /tmp/venv/bin/activate
                python3 -m pytest -p no:cacheprovider -vvv \\
                    $TEST_FILE_TAT_COAP_COMMON \\
                    $TEST_FILE_TAT_COAP_CORE \\
                    $TEST_FILE_TAT_COAP_OBSERVE \\
                    $TEST_FILE_TAT_COAP_BLOCK \\
                    --pastebin=all
            '''
      }

      stage("Analyzer unittesting"){
            sh '''
                . /tmp/venv/bin/activate
                python3 -m pytest -p no:cacheprovider -vvv \\
                    $TEST_FILE_ANALYZER_TESTS \\
                    --pastebin=all
            '''
      }

      stage("Dissector unittesting"){
            sh '''
                . /tmp/venv/bin/activate
                python3 -m pytest -p no:cacheprovider -vvv \\
                    $TEST_FILE_DISSECTOR_TESTS \\
                    --pastebin=all
            '''
      }

      stage("unittesting rest of component"){
            sh '''
                . /tmp/venv/bin/activate
                python3 -m pytest -p no:cacheprovider -vvv tests/ \\
                --ignore=$TEST_FILE_TAT_COAP_COMMON \\
                --ignore=$TEST_FILE_TAT_COAP_CORE \\
                --ignore=$TEST_FILE_TAT_COAP_OBSERVE \\
                --ignore=$TEST_FILE_TAT_COAP_BLOCK \\
                --ignore=tests/test_webserver/tests.py \\
                --ignore=tests/test_tat/test_webserver.py \\
                --ignore=$TEST_FILE_DISSECTOR_TESTS \\
                --ignore=$TEST_FILE_ANALYZER_TESTS \\
            '''
        }
    }
}
