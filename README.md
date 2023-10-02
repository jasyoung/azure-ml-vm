---
languages:
- python
products:
- azure
- azure-machine-learning-service
description: "CLI for starting, stopping, sshing, and other ways of interacting with your Azure ML VM instance"
---

# MLOps with Azure ML

command line options

mlvm setup
- You will be prompted to create your own azure ml vm which will be found here: https://ml.azure.com/compute/list/instances?wsid=/subscriptions/a1eab4f0-e17c-4e70-ab04-833c063dc515/resourceGroups/dt-datascience-core-dev-usw2/providers/Microsoft.MachineLearningServices/workspaces/dt-datascience-core-dev-usw2&tid=1aff0669-ee5f-40b8-9800-b5ec4f39c48e
- If you already have one, then just enter your instance name when prompted
- After that is set up, you will configure the mlvm CLI tool to interact with your instance
mlvm start
- start your vm instance
mlvm stop
- stop your vm instance
mlvm ssh
- ssh into your vm instance
