def get_failed_logins(es):

    query = {
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "event.code": "4625"
                        }
                    },
                    {
                        "terms": {
                            "winlog.event_data.LogonType": [
                                "3",
                                "10"
                            ]
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-30s"
                            }
                        }
                    }
                ]
            }
        }
    }

    response = es.search(
        index="logs-*",
        body=query
    )

    return response["hits"]["hits"]
