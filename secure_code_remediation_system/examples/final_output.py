def vulnerable_lookup(request, cursor):
    user_id = request.args.get("id")
    safe_user_id = parametrize(user_id)
    query = "SELECT * FROM users WHERE id = " + safe_user_id
    cursor.execute(query)
