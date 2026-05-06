def vulnerable_lookup(request, cursor):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
