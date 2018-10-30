    def userInput

   stage('Preparation') { // for display purposes

    try {
        userInput = input(
            id: 'Proceed1', message: 'Was this successful?', parameters: [
            [$class: 'BooleanParameterDefinition', defaultValue: true, description: '', name: 'Please confirm you agree with this']
            ])
    } catch(err) { // input false
        def user = err.getCauses()[0].getUser()
        userInput = false
        echo "Aborted by: [${user}]"
    }

    node {
        if (userInput == true) {
            // do something
            echo "this was successful"
        } else {
            // do something else
            echo "this was not successful"
            currentBuild.result = 'FAILURE'
        }
    }

   }
   stage('Build') {
      sh("ansible-playbook -i inventory getip.yml")
   }
