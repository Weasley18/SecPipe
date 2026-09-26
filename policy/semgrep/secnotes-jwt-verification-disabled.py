import jwt


def bad_no_verify(token):
    # ruleid: secnotes-jwt-verification-disabled
    return jwt.decode(token, options={"verify_signature": False})


def bad_no_verify_with_key(token, key):
    # ruleid: secnotes-jwt-verification-disabled
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_aud": False, "verify_signature": False})


def bad_alg_none(token, key):
    # ruleid: secnotes-jwt-verification-disabled
    return jwt.decode(token, key, algorithms=["HS256", "none"])


def bad_unpinned(token, key):
    # ruleid: secnotes-jwt-verification-disabled
    return jwt.decode(token, key)


def good(token, key):
    # ok: secnotes-jwt-verification-disabled
    return jwt.decode(token, key, algorithms=["HS256"], audience="secnotes-api", issuer="secnotes")
