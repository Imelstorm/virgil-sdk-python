errors_list = {
    10000: "Internal application error",
    10010: "Controller was not found.",
    10020: "Action was not found.",
    10100: "JSON specified as a request body is invalid",
    20000: "Request wrongly encoded.",
    20010: "Request JSON invalid.",
    20020: "Request 'response_password' parameter invalid.",
    20100: "The request UUID header was used already",
    20101: "The request UUID header is invalid",
    20200: "The request sing header not found",
    20201: "The Public Key UUID header not specified or incorrect",
    20202: "The request sign header is invalid",
    20203: "Public Key value is required in request body",
    20204: "Public Key value in request body must be base64 encoded value",
    20205: "Public Key UUIDs in URL part and X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID header must match",
    20206: "The public key id in the request body is invalid ",
    20207: "Public Key UUIDs in Request and X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID header must match",
    20300: "The Virgil application token was not specified or invalid",
    20301: "The Virgil statistics application error",
    30001: "The entity not found by specified UUID",
    30010: "Private Key not specified.",
    30020: "Private Key not base64 encoded.",
    30100: "Public Key object not found by specified UUID",
    30101: "Public key length invalid",
    30102: "Public key must be base64-encoded string",
    30200: "Identity object is not found for id specified",
    30201: "Identity type is invalid. Valid types are: 'email', 'application'",
    30202: "Email value specified for the email identity is invalid",
    30203: "Cannot create unconfirmed application identity",
    30300: "Virgil Card object not found for id specified",
    30301: "Virgil Card custom data list must be an array",
    30302: "Virgil Card custom data entries cannot start with reserved 'vc_' prefix",
    30303: "Virgil Card custom data entries cannot have empty and too long keys",
    30304: "Virgil Card custom data entries keys contains invalid characters",
    30305: "Virgil Card custom data entry value length validation failed",
    30306: "Virgil Card cannot sign itself",
    30400: "Sign object not found for id specified",
    30402: "The signed digest value is invalid",
    30403: "Sign Signed digest must be base64 encoded string",
    30404: "Cannot save the Sign because it exists already",
    31000: "Value search parameter is mandatory",
    31010: "Search value parameter is mandatory for the application search",
    31020: "Virgil Card's signs parameter must be an array",
    31030: "Identity validation token is invalid",
    31040: "Virgil Card revokation parameters do not match Virgil Card's identity",
    31050: "Virgil Identity service error",
    31060: "Identities parameter is invalid",
    31070: "Identity validation failed",
    40000: "Virgil Card ID not specified.",
    40010: "Virgil Card ID has incorrect format.",
    40020: "Virgil Card ID not found.",
    40030: "Virgil Card ID already exists.",
    40040: "Virgil Card ID not found in Public Key service.",
    40050: "Virgil Card ID not found for provided Identity",
    40100: "Identity type is invalid",
    40110: "Identity's ttl is invalid",
    40120: "Identity's ctl is invalid",
    40130: "Identity's token parameter is missing",
    40140: "Identity's token doesn't match parameters",
    40150: "Identity's token has expired",
    40160: "Identity's token cannot be decrypted",
    40170: "Identity's token parameter is invalid",
    40180: "Identity is not unconfirmed",
    40190: "Hash to be signed parameter is invalid",
    40200: "Email identity value validation failed",
    40210: "Identity's confirmation code is invalid",
    40300: "Application value is invalid",
    40310: "Application's signed message is invalid",
    41000: "Identity entity was not found",
    41010: "Identity's confirmation period has expired",
    50000: "Request Sign UUID not specified.",
    50010: "Request Sign UUID has wrong format.",
    50020: "Request Sign UUID already exists.",
    50030: "Request Sign is incorrect.",
    60000: "Identity not specified.",
    60010: "Identity Type not specified.",
    60020: "Identity Value not specified.",
    60030: "Identity Token not specified.",
    90000: "Identity validation under RA service failed.",
    90010: "Access Token validation under Stats service failed."
}
