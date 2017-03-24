class Schemata(object):
    GRANT_SCHEMA = {
        "oneOf": [
            {
                "type": "object",
                "description": "Grant for username-password authentication",
                "properties": {
                    "grant_type": {
                        "enum": ["password"]
                    },
                    "client_id": {
                        "type": "string"
                    },
                    "username": {
                        "type": "string"
                    },
                    "password": {
                        "type": "string"
                    },
                    "scope": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    }
                },
                "required": [
                    "client_id", "grant_type", "username", "password", "scope"
                ]
            },
            {
                "type": "object",
                "description": "Grant for refresh-token authentication",
                "properties": {
                    "client_id": {
                        "type": "string"
                    },
                    "grant_type": {
                        "enum": ["refresh_token"]
                    },
                    "refresh_token": {
                        "type": "string"
                    }
                },
                "required": ["client_id", "grant_type", "refresh_token"]
            },
            {
                "type": "object",
                "description": "Grant for client credentials authorization",
                "properties": {
                    "client_id": {
                        "type": "string"
                    },
                    "grant_type": {
                        "enum": ["client_credentials"]
                    },
                    "client_secret": {
                        "type": ["null", "string"]
                    },
                    "scope": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    }
                },
                "required": [
                    "grant_type", "client_id", "client_secret", "scope"
                ]
            }
        ]
    }

    REVOKE_SCHEMA = {
        "type": "object",
        "properties": {
            "access_token": {
                "type": "string"
            }
        },
        "required": ["access_token"]
    }
