key_store = {}

def store_agent(victim_id, data):
    key_store[victim_id] = data


def get_agent(victim_id):
    return key_store.get(victim_id)


def get_all_agents():
    return key_store


def remove_agent(victim_id):
    if victim_id in key_store:
        del key_store[victim_id]


def clear_store():
    key_store.clear()
