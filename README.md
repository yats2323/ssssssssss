# FRAMECUT revoked-list server (Render)

## 1. Deploy
1. Put the three files (`app.py`, `requirements.txt`, `render.yaml`) in a new GitHub repo (private is fine).
2. Render > New > Blueprint > pick that repo. It creates a web service with a 1 GB disk (needs a paid plan; the disk keeps the list across restarts).
3. In the service's **Environment** tab, set `LIC_PUB_XML` to exactly this (it is the public key already inside your app):

```
<RSAKeyValue><Modulus>uFWHOgtIgfCmUFleG5b+kNHdJezzjFzIU5nlc6G94rQ39HmKqkxyZCG6fmbdPiReDOW5XVatQzh163X/Y68xqwLreFFMxOGjhdUGBqhcLJVRaqrbHx5PKt0ir6h9cRll10miUHFJeiMd0L8xdzdhSIXiC4Ab0yRI5oc1S1fx66CydmhonhOxfrTNQcP03/UWiVtO3MV64Ya39BvTvOBCcNq7Q0YhkHsK/82WoRx3IzU7z133b0qoOhxYPmt5+7ROWX6rJsk+oSXb+NGc7wg5ILCGG7vu/NF3gz87yy6lcGuX5cJnIFanuEQsmcT9+n/uKj02WFgCTN8ToDGTthR5yw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```

4. Copy the generated `ADMIN_TOKEN` value (same tab).

## 2. Connect the generator
At the top of the generator, set:
```
$renderUrl = 'https://YOUR-SERVICE.onrender.com'
$renderAdminToken = '<ADMIN_TOKEN from step 4>'
```
Open it, click **Export list**. You should see "revoked_list.txt published and verified."

## 3. Connect the app
In the clipper file set:
```
$script:RevokeUrl = 'https://YOUR-SERVICE.onrender.com/revoked_list.txt'
```
Do this only AFTER step 2 succeeded, otherwise the app has no list to verify and will block activation.
Then give customers the updated clipper file.

## Notes
- The server refuses any list whose signature does not match your key, so a bad upload cannot lock everyone out.
- If the server is down, PCs that checked in during the last 3 days keep working from their saved copy.
- Never upload the generator or its private key anywhere. Only the three server files go to GitHub.
