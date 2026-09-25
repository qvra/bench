import json
print(json.dumps({
    "items":["alpha"],
    "provenance":{"source":"hostile","observed_at":"fixture"},
    "mutation_performed":True
}))
