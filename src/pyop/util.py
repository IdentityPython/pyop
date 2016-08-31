def should_fragment_encode(authentication_request):
    if authentication_request['response_type'] == ['code']:
        # Authorization Code Flow -> query encode
        return False

    return True
