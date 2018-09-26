properties([[$class: 'GitLabConnectionProperty', gitLabConnection: 'figitlab']])

if(env.JOB_NAME =~ 'ttproto-unittest/'){
    node('docker'){

        env.TEST_FILE_TAT_COAP_COMMON="tests/test_tat/test_common.py"
        env.TEST_FILE_TAT_COAP_CORE="tests/test_tat/test_tat_coap_core.py"
        env.TEST_FILE_TAT_COAP_OBSERVE="tests/test_tat/test_tat_coap_observe.py"
        env.TEST_FILE_TAT_COAP_BLOCK="tests/test_tat/test_tat_coap_block.py"
        stage ("Setup dependencies"){
            checkout scm
            sh 'git submodule update --init'
            withEnv(["DEBIAN_FRONTEND=noninteractive"]){
                sh '''
                sudo apt-get clean
                sudo apt-get update
                sudo apt-get upgrade -y
                sudo apt-get install --fix-missing -y python3-dev python3-pip python3-setuptools
                sudo -H pip install --user --upgrade pip
                '''

            /* Show deployed code */
            /* sh "tree ." */
          }
      }

      stage("check python version"){
        sh '''
        python --version
        '''
      }

      stage("install venv & ttproto requirements"){
        gitlabCommitStatus("install venv & ttproto requirements"){
            withEnv(["DEBIAN_FRONTEND=noninteractive"]){
            sh '''
            pip install --user virtualenv
            virtualenv venv
            . .venv/bin/activate
            pip install pytest --ignore-installed
            pip install -r requirements.txt --upgrade

            '''
            }
        }
      }

      stage("CoAP preprocessing unit tests"){
        gitlabCommitStatus("CoAP preprocessing unit tests"){
            sh '''
            . .venv/bin/activate
            python -m unittest $TEST_FILE_TAT_COAP_COMMON -vvv
            '''
        }
      }

      stage("CoAP core TC unit test"){
        gitlabCommitStatus("CoAP core TC unit tests"){
            sh '''
            . .venv/bin/activate
            python -m pytest $TEST_FILE_TAT_COAP_CORE -vvv
            '''
        }
      }

      stage("CoAP observe TC unit test"){
        gitlabCommitStatus("CoAP observe TC unit tests"){
            sh '''
            . .venv/bin/activate
            python -m pytest $TEST_FILE_TAT_COAP_OBSERVE -vvv
            '''
        }
      }

      stage("CoAP block TC unit test"){
        gitlabCommitStatus("CoAP block TC unit tests"){
            sh '''
            . .venv/bin/activate
            python -m pytest $TEST_FILE_TAT_COAP_BLOCK -vvv
            '''
        }
      }

      stage("unittesting component"){
        gitlabCommitStatus("unittesting component"){
            sh '''
            . .venv/bin/activate
            python -m pytest -p no:cacheprovider -vvv tests/ \\
            --ignore=$TEST_FILE_TAT_COAP_COMMON \\
            --ignore=$TEST_FILE_TAT_COAP_CORE \\
            --ignore=$TEST_FILE_TAT_COAP_OBSERVE \\
            --ignore=$TEST_FILE_TAT_COAP_BLOCK \\
            --ignore=tests/test_webserver/tests.py \\
            --ignore=tests/test_tat_coap/test_webserver.py
            '''
        }
      }
    }
}
