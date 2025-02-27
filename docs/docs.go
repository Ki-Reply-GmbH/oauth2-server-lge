// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "API Support",
            "url": "https://cariad.example.com/support",
            "email": "support@cariad.example.com"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/": {
            "get": {
                "description": "Returns the health status of the server",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "system"
                ],
                "summary": "Health check",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.HealthResponse"
                        }
                    }
                }
            }
        },
        "/.well-known/jwks.json": {
            "get": {
                "description": "Returns the JSON Web Key Set for token verification",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "oauth2"
                ],
                "summary": "Get JWKS",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    },
                    "405": {
                        "description": "Method Not Allowed",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/introspect": {
            "post": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "description": "Validates a token and returns its metadata if active",
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "oauth2"
                ],
                "summary": "Introspect a token",
                "parameters": [
                    {
                        "type": "string",
                        "description": "The token to introspect",
                        "name": "token",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "405": {
                        "description": "Method Not Allowed",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/token": {
            "post": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "description": "Creates a new JWT token using client credentials flow",
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "oauth2"
                ],
                "summary": "Issue a new OAuth2 token",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Grant type (must be client_credentials)",
                        "name": "grant_type",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Space-separated list of requested scopes",
                        "name": "scope",
                        "in": "formData"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.TokenResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    },
                    "405": {
                        "description": "Method Not Allowed",
                        "schema": {
                            "$ref": "#/definitions/main.ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "main.ErrorResponse": {
            "description": "Error response structure",
            "type": "object",
            "properties": {
                "error": {
                    "description": "OAuth2 error code",
                    "type": "string"
                },
                "error_description": {
                    "description": "Human-readable error description",
                    "type": "string"
                }
            }
        },
        "main.HealthResponse": {
            "description": "Health check response",
            "type": "object",
            "properties": {
                "status": {
                    "description": "Status of the server (ok when healthy)",
                    "type": "string"
                }
            }
        },
        "main.TokenResponse": {
            "description": "Successful token response",
            "type": "object",
            "properties": {
                "access_token": {
                    "description": "JWT access token",
                    "type": "string"
                },
                "expires_in": {
                    "description": "Time in seconds until the token expires",
                    "type": "integer"
                },
                "scope": {
                    "description": "Space-separated scopes granted to the token",
                    "type": "string"
                },
                "token_type": {
                    "description": "Type of the token (always Bearer)",
                    "type": "string"
                }
            }
        }
    },
    "securityDefinitions": {
        "BasicAuth": {
            "type": "basic"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0.0",
	Host:             "auth.cariad.example.com",
	BasePath:         "/",
	Schemes:          []string{"https"},
	Title:            "Simple OAuth2 Server API",
	Description:      "Health check response",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
