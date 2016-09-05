def should_fragment_encode(authentication_request):
    if authentication_request['response_type'] == ['code']:
        # Authorization Code Flow -> query encode
        return False

    return True


def is_allowed_response_type(response_type, supported_response_types):
    return frozenset(response_type) in [frozenset(rt.split()) for rt in supported_response_types]


def find_common_values(preference_values, supported_values):
    unordered_preference_values = {frozenset(p.split()) for p in preference_values}
    unordered_supported_values = {frozenset(s.split()) for s in supported_values}
    return unordered_supported_values.intersection(unordered_preference_values)


def requested_scope_is_allowed(requested_scope, allowed_scope):
    return frozenset(requested_scope).issubset(frozenset(allowed_scope.split()))
