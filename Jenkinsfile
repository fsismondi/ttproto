properties([[$class: 'GitLabConnectionProperty', gitLabConnection: 'figitlab']])

if(env.JOB_NAME =~ 'ttproto-unittest/'){
    node('sudo'){

        stage ("Setup dependencies"){
            checkout scm
            sh 'git submodule update --init'
            withEnv(["DEBIAN_FRONTEND=noninteractive"]){
                sh '''
                sudo apt-get clean
                sudo apt-get update
                sudo apt-get upgrade -y
                sudo apt-get install --fix-missing -y python3-dev python3-pip python3-setuptools
                sudo -H pip install pytest --ignore-installed
                '''

            /* Show deployed code */
            sh "tree ."
          }
      }

      stage("ttproto requirements"){
        gitlabCommitStatus("ttproto requirements"){
            withEnv(["DEBIAN_FRONTEND=noninteractive"]){
            sh '''
            sudo -H pip3 install -r requirements.txt --upgrade

            '''
            }
        }
      }

      stage("unittesting component"){
        gitlabCommitStatus("unittesting component"){
            sh '''
            python3 -m pytest tests/  --ignore=tests/test_webserver/tests.py  --ignore=tests/test_tat_coap/test_webserver.py -vvv
            '''
        }
      }

    }
}

