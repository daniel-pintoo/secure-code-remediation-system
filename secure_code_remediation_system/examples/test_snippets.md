# Visual API Test Snippets

Paste any of these snippets into the visual interface at `http://127.0.0.1:8000`.

## SQL Injection

```python
def vulnerable_lookup(request, cursor):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
```

## XSS

```python
def vulnerable_profile(request):
    display_name = request.args.get("name")
    html = "<h1>" + display_name + "</h1>"
    render_template_string(html)
```

## Command Injection

```python
def vulnerable_command(request):
    host = request.args.get("host")
    command = "ping -c 1 " + host
    system(command)
```

## Path Traversal

```python
def vulnerable_download(request):
    filename = request.args.get("file")
    open(filename)
```

## SSRF

```python
def vulnerable_fetch(request):
    target_url = request.args.get("url")
    urlopen(target_url)
```
