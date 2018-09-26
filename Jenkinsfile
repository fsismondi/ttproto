properties([[$class: 'GitLabConnectionProperty', gitLabConnection: 'figitlab']])

if(env.JOB_NAME =~ 'ttproto-unittest/'){
    node('docker'){

        env.TEST_FILE_TAT_COAP_COMMON="tests/test_tat/test_common.py"
        env.TEST_FILE_TAT_COAP_CORE="tests/test_tat/test_tat_core.py"
        env.TEST_FILE_TAT_COAP_OBSERVE="tests/test_tat/test_tat_observe.py"
        env.TEST_FILE_TAT_COAP_BLOCK="tests/test_tat/test_tat_block.py"
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

      stage("install venv & ttproto requirements"){
        gitlabCommitStatus("install venv & ttproto requirements"){
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
      }

      stage("CoAP preprocessing unit tests"){
        gitlabCommitStatus("CoAP preprocessing unit tests"){
            sh '''
            . /tmp/venv/bin/activate
            python3 -m unittest $TEST_FILE_TAT_COAP_COMMON -vvv
            '''
        }
      }

      stage("CoAP core TC unit test"){
        gitlabCommitStatus("CoAP core TC unit tests"){
            sh '''
            . /tmp/venv/bin/activate
            python3 -m pytest $TEST_FILE_TAT_COAP_CORE -vvv
            '''
        }
      }

      stage("CoAP observe TC unit test"){
        gitlabCommitStatus("CoAP observe TC unit tests"){
            sh '''
            . /tmp/venv/bin/activate
            python3 -m pytest $TEST_FILE_TAT_COAP_OBSERVE -vvv
            '''
        }
      }

      stage("CoAP block TC unit test"){
        gitlabCommitStatus("CoAP block TC unit tests"){
            sh '''
            . /tmp/venv/bin/activate
            python3 -m pytest $TEST_FILE_TAT_COAP_BLOCK -vvv
            '''
        }
      }

      stage("unittesting component"){
        gitlabCommitStatus("unittesting component"){
            sh '''
            . /tmp/venv/bin/activate
            python3 -m pytest -p no:cacheprovider -vvv tests/ \\
            --ignore=$TEST_FILE_TAT_COAP_COMMON \\
            --ignore=$TEST_FILE_TAT_COAP_CORE \\
            --ignore=$TEST_FILE_TAT_COAP_OBSERVE \\
            --ignore=$TEST_FILE_TAT_COAP_BLOCK \\
            --ignore=tests/test_webserver/tests.py \\
            --ignore=tests/test_tat/test_webserver.py
            '''
        }
      }
    }
}
